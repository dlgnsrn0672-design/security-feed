"""국가사이버안보센터(NCSC) 보안권고문·공지사항 권고·지침·가이드 신규 글 → 텔레그램 알림 (CVE 전용 봇)

NCSC 사이트는 메뉴 주소가 접속마다 바뀌고 목록을 브라우저 스크립트로 그려서
헤드리스 브라우저(Playwright)로 메뉴 이름을 찾아 들어가 읽음.
공지사항은 행사·모집 같은 일반 글을 빼고 권고만, 권고는 KISA 보안공지와 같은 내용이면 건너뜀.

실행:  python ncsc_watch.py [--dry-run] [--latest N]
"""
import argparse
import asyncio
import html
import json
import logging
import os
import re
import time
from pathlib import Path

from playwright.async_api import async_playwright

from common import Bot, hide_products, product_line
from kisa_watch import same_story, token_df

TOKEN = (os.getenv("CVE_TELEGRAM_TOKEN") or "").strip() or os.getenv("TELEGRAM_TOKEN", "").strip()
CHAT_ID = (os.getenv("CVE_TELEGRAM_CHAT_ID") or "").strip() or os.getenv("TELEGRAM_CHAT_ID", "").strip()
STATE_FILE = Path(__file__).with_name("ncsc_state.json")
KISA_STATE_FILE = Path(__file__).with_name("kisa_state.json")
BASE = "https://www.ncsc.go.kr"
MAIN = BASE + "/ko/main/main.html"
# 공지사항에서 보안 권고로 보는 제목 (행사·공모전·모집·보고서 발간 같은 공지는 제외)
ADVISORY = re.compile(r"권고|주의|경보|경고|취약점|해킹|공격|악성|랜섬|피싱|스미싱|사칭|유출|침해|보안\s*업데이트|긴급|위협")
NOT_ADVISORY = re.compile(r"공모전|모집|채용|개최|행사|서포터즈|설문|교육생|세미나")
# (키, 메뉴 이름, 알림 제목, 원문 위치, 권고 여부)
BOARDS = [
    ("advice", "보안권고문", "🛡️ <b>국가사이버안보센터 보안권고문</b>", "알림마당 → 보안권고문", True),
    ("notice", "공지사항", "🛡️ <b>국가사이버안보센터 보안 권고</b>", "알림마당 → 공지사항", True),
    ("guide", "지침·가이드", "📘 <b>국가사이버안보센터 지침·가이드 신규</b>", "자료실 → 지침·가이드", False),
]

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ncsc_watch")


async def read_board(page, href):
    """게시판 목록 [{title, kind, date}] (최신순)"""
    await page.goto(BASE + href, wait_until="load", timeout=90000)
    await page.wait_for_timeout(3000)
    rows = await page.eval_on_selector_all("tr", """rows => rows.map(r => {
        const a = r.querySelector('a');
        return [r.innerText.replace(/\\s+/g, ' ').trim(), a ? a.innerText.replace(/\\s+/g, ' ').trim() : ''];
    })""")
    items = []
    for text, title in rows:
        m = re.search(r"(20\d\d[.\-]\d\d[.\-]\d\d)\s*$", text)
        if not m:
            continue
        head = re.sub(r"^(공지|\d+)\s+", "", text[:m.start()]).strip()
        if title and title in head:
            kind = head[:head.index(title)].strip()
        else:
            # 구분(공지사항·가이드·지침·기타 공시 등) 뒤가 제목
            k = re.match(r"(공지사항|가이드|지침|기타 공시|기타|보안권고문?)\s+", head)
            kind, title = (k.group(1), head[k.end():]) if k else ("", head)
        items.append({"title": title.strip(), "kind": kind, "date": m.group(1).replace("-", ".")})
    return items


async def main_links(page):
    """메인 화면의 메뉴 링크 [(이름, 주소)] — 느릴 때 한 번 더 시도"""
    for attempt in range(2):
        try:
            await page.goto(MAIN, wait_until="load", timeout=90000)
            break
        except Exception as e:
            if attempt:
                raise
            log.warning("NCSC 접속 지연, 다시 시도: %s", e)
    await page.wait_for_timeout(3000)
    return await page.eval_on_selector_all(
        "a", "els => els.map(e => [e.textContent.replace(/\\s+/g, ' ').trim(), e.getAttribute('href') || ''])")


async def fetch_boards():
    """{키: 목록} — 메뉴 이름으로 게시판 주소를 찾아 들어감 (주소가 접속마다 바뀜)"""
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(locale="ko-KR")
        result = {}
        for key, menu, *_ in BOARDS:
            # 메뉴 주소(토큰)는 방금 연 메인 화면에서만 유효해서 게시판마다 메인부터 다시 들어감
            try:
                links = await main_links(page)
            except Exception as e:
                log.warning("NCSC 메인 접속 실패: %s", e)
                break
            href = next((h for t, h in links if t == menu and "PageLink" in h), None)
            if key == "notice" and not href:
                href = next((h for t, h in links if t == "더보기" and "PageLink" in h), None)
            if not href:
                log.warning("'%s' 메뉴를 찾지 못함 (사이트 구조 변경 가능성)", menu)
                continue
            try:
                result[key] = await read_board(page, href)
            except Exception as e:
                log.warning("'%s' 목록 조회 실패: %s", menu, e)
        await browser.close()
    return result


def build_message(item, title_line, where):
    lines = [title_line, "", f"<b>{html.escape(item['title'])}</b>"]
    if product_line(item["title"]):
        lines.append(product_line(item["title"]))
    meta = f"구분: {html.escape(item['kind'])} · " if item.get("kind") and item["kind"] not in ("공지사항",) else ""
    lines += [f"{meta}등록: {item['date']}", "",
              f'🔗 <a href="{html.escape(MAIN)}">국가사이버안보센터</a> → {where}에서 원문 확인']
    return "\n".join(lines)


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="전송하지 않고 출력만 (상태 저장 안 함)")
    parser.add_argument("--latest", type=int, default=0, help="이미 본 글이어도 게시판별 최신 N건을 다시 전송")
    args = parser.parse_args()

    state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
    if "seen" in state:  # 예전 형식(공지사항만) → 게시판별 형식
        state = {"boards": {"notice": state["seen"]}}
    boards_seen = state.setdefault("boards", {})
    boards = await fetch_boards()
    kisa = json.loads(KISA_STATE_FILE.read_text()).get("kisa_titles", []) if KISA_STATE_FILE.exists() else []
    key_of = lambda it: f"{it['date']} {it['title']}"
    bot = None if args.dry_run else Bot(TOKEN)
    sent_titles = []  # 보안권고문과 공지사항에 같은 글이 올라오면 한 번만

    for key, menu, title_line, where, advisory in BOARDS:
        if not boards.get(key):
            # 목록을 못 읽었으면 기록을 건드리지 않음 (빈 기록이 남으면 다음에 기존 글이 전부 새 글로 보임)
            log.warning("%s: 목록을 읽지 못해 이번에는 건너뜀", menu)
            continue
        items = boards[key]
        if key == "notice":
            items = [it for it in items if ADVISORY.search(it["title"]) and not NOT_ADVISORY.search(it["title"])]
        first = key not in boards_seen
        seen = boards_seen.get(key, [])
        new = [it for it in items if key_of(it) not in seen]
        to_send = items[:args.latest] if args.latest else ([] if first else new)
        kept = []
        if advisory:
            df = token_df([r["title"] for r in kisa] + [it["title"] for it in to_send])
        for it in to_send:
            if it["title"] in sent_titles:
                continue
            dup = advisory and next((r["title"] for r in kisa if same_story(it["title"], r["title"], df)), None)
            if dup:
                log.info("KISA와 중복이라 건너뜀: %s ← %s", it["title"], dup)
                continue
            kept.append(it)
        for it in reversed(kept):
            text = build_message(it, title_line, where)
            sent_titles.append(it["title"])
            if args.dry_run:
                print(hide_products(text), "\n" + "-" * 60)
            else:
                await bot.send_message(chat_id=CHAT_ID, text=text, parse_mode="HTML", disable_web_page_preview=True)
                await asyncio.sleep(3)
        log.info("%s: %d건 중 새 글 %d건, 알림 %d건%s", menu, len(items), len(new), len(kept),
                 " (첫 실행: 기록만)" if first and not args.latest else "")
        boards_seen[key] = (seen + [key_of(it) for it in new if key_of(it) not in seen])[-500:]

    if not args.dry_run:
        state["checked"] = time.time()
        STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    asyncio.run(main())
