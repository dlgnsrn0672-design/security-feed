"""국가사이버안보센터(NCSC) 공지사항의 보안 권고 → 텔레그램 알림 (CVE 전용 봇)

NCSC 사이트는 목록을 브라우저 스크립트로 그려서 헤드리스 브라우저(Playwright)로 읽음.
행사·모집 같은 일반 공지는 빼고 보안 권고만, KISA 보안공지와 같은 내용이면 건너뜀.

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
# 보안 권고로 보는 제목 (행사·공모전·모집·보고서 발간 같은 공지는 제외)
ADVISORY = re.compile(r"권고|주의|경보|경고|취약점|해킹|공격|악성|랜섬|피싱|스미싱|사칭|유출|침해|보안\s*업데이트|긴급|위협")
NOT_ADVISORY = re.compile(r"공모전|모집|채용|개최|행사|서포터즈|설문|교육생|세미나")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ncsc_watch")


async def fetch_notices():
    """공지사항 목록 [{title, date, link}] (최신순)"""
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(locale="ko-KR")
        await page.goto(MAIN, wait_until="load", timeout=60000)
        await page.wait_for_timeout(3000)
        links = await page.eval_on_selector_all(
            "a", "els => els.map(e => [e.innerText.trim(), e.getAttribute('href') || ''])")
        more = next((h for t, h in links if t == "더보기" and "PageLink" in h), None)
        if not more:
            raise RuntimeError("공지사항 '더보기' 링크를 찾지 못함 (사이트 구조 변경 가능성)")
        await page.goto(BASE + more, wait_until="load", timeout=60000)
        await page.wait_for_timeout(3000)
        rows = await page.eval_on_selector_all("tr", """rows => rows.map(r => {
            const a = r.querySelector('a');
            return [r.innerText.replace(/\\s+/g, ' ').trim(), a ? a.innerText.trim() : '', a ? (a.getAttribute('href') || '') : ''];
        })""")
        await browser.close()
    items = []
    for text, title, href in rows:
        m = re.search(r"(20\d\d[.\-]\d\d[.\-]\d\d)\s*$", text)
        if not m:
            continue
        if not title:
            # 제목 칸: '번호 공지사항 제목 날짜' 형식에서 앞뒤를 떼어 냄
            title = re.sub(r"^(공지|\d+)\s+공지사항\s+", "", text[:m.start()]).strip()
        items.append({"title": title, "date": m.group(1).replace("-", "."),
                      "link": BASE + href if href.startswith("/") else MAIN})
    return items


def build_message(item):
    lines = ["🛡️ <b>국가사이버안보센터 보안 권고</b>", "", f"<b>{html.escape(item['title'])}</b>"]
    if product_line(item["title"]):
        lines.append(product_line(item["title"]))
    lines += [f"게시: {item['date']}", "",
              f'🔗 <a href="{html.escape(MAIN)}">국가사이버안보센터</a> → 알림마당 → 공지사항에서 원문 확인']
    return "\n".join(lines)


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="전송하지 않고 출력만 (상태 저장 안 함)")
    parser.add_argument("--latest", type=int, default=0, help="이미 본 글이어도 최신 권고 N건을 다시 전송")
    args = parser.parse_args()

    state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
    first = "seen" not in state
    seen = state.get("seen", [])
    items = await fetch_notices()
    log.info("NCSC 공지 %d건 조회", len(items))
    advisories = [it for it in items if ADVISORY.search(it["title"]) and not NOT_ADVISORY.search(it["title"])]
    keys = lambda it: f"{it['date']} {it['title']}"
    new = [it for it in advisories if keys(it) not in seen]
    to_send = advisories[:args.latest] if args.latest else ([] if first else new)

    # KISA 보안공지와 같은 내용이면 건너뜀
    kisa = json.loads(KISA_STATE_FILE.read_text()).get("kisa_titles", []) if KISA_STATE_FILE.exists() else []
    df = token_df([r["title"] for r in kisa] + [it["title"] for it in to_send])
    kept = []
    for it in to_send:
        dup = next((r["title"] for r in kisa if same_story(it["title"], r["title"], df)), None)
        if dup:
            log.info("KISA와 중복이라 건너뜀: %s ← %s", it["title"], dup)
        else:
            kept.append(it)

    bot = None if args.dry_run else Bot(TOKEN)
    for it in reversed(kept):
        text = build_message(it)
        if args.dry_run:
            print(hide_products(text), "\n" + "-" * 60)
        else:
            await bot.send_message(chat_id=CHAT_ID, text=text, parse_mode="HTML", disable_web_page_preview=True)
            await asyncio.sleep(3)
    log.info("보안 권고 %d건 중 새 글 %d건, 알림 %d건%s", len(advisories), len(new), len(kept),
             " (첫 실행: 기록만)" if first and not args.latest else "")
    if not args.dry_run:
        state["seen"] = (seen + [keys(it) for it in new if keys(it) not in seen])[-500:]
        state["checked"] = time.time()
        STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    asyncio.run(main())
