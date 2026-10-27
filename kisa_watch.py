"""KISA(보호나라/KNVD) 보안공지·보안뉴스·데일리시큐 → 텔레그램 알림 (CVE 전용 봇)

실행:  python kisa_watch.py [--dry-run]
"""
import argparse
import asyncio
import html
import json
import logging
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urljoin


import https_only
from common import CHAT_ID, TOKEN, Bot

TOKEN = (os.getenv("CVE_TELEGRAM_TOKEN") or "").strip() or TOKEN
CHAT_ID = (os.getenv("CVE_TELEGRAM_CHAT_ID") or "").strip() or CHAT_ID

STATE_FILE = Path(__file__).with_name("kisa_state.json")
# 피드별로 주소를 앞에서부터 시도해서 처음 성공하는 곳을 사용 (RSS → 목록 페이지 순)
FEEDS = {
    "kisa": ("🇰🇷", "KISA 보안공지", (
        "https://knvd.krcert.or.kr/rss/securityNotice.do",
        "https://www.boho.or.kr/kr/rss.do?bbsId=B0000133",
        "https://knvd.krcert.or.kr/securityNotice.do",
        "https://www.boho.or.kr/kr/bbs/list.do?menuNo=205020&bbsId=B0000133",
    )),
    "boannews": ("📰", "보안뉴스", ("https://www.boannews.com/rss/S1N2.xml",)),
    "dailysecu": ("🗞", "데일리시큐", (
        "https://www.dailysecu.com/rss/allArticle.xml",
        "https://www.dailysecu.com/rss/S1N1.xml",
    )),
}
FILTERED_FEEDS = {"dailysecu"}


# 보안 단어가 들어가도 실무 정보가 아닌 연재물은 제외
EXCLUDE_KEYWORDS = ("연재소설",)


def is_security_news(title):
    low = title.lower()
    if any(k in low for k in EXCLUDE_KEYWORDS):
        return False
    return any(k in low for k in SECURITY_KEYWORDS)
# 처음 실행할 때 피드별로 최근 몇 건만 보냄 (0이면 기존 글은 기록만)
FIRST_RUN_SHOW = int(os.getenv("FEED_FIRST_RUN_SHOW", "3"))
# 일반 IT 기사가 섞인 피드는 제목에 이 단어가 있는 기사만 보냄
SECURITY_KEYWORDS = (
    "취약점", "해킹", "해커", "랜섬웨어", "유출", "침해", "악성코드", "악성 ", "피싱", "스미싱",
    "제로데이", "보안 업데이트", "보안업데이트", "패치", "백도어", "디도스", "ddos", "apt",
    "공격", "탈취", "사이버", "보안사고", "개인정보", "cve", "익스플로잇", "봇넷", "스파이웨어",
    "다크웹", "정보유출", "인증정보", "계정", "경보",
)
MAX_SEEN = 1000

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)
log = logging.getLogger("kisa_watch")


def parse_rss(raw):
    """bytes RSS 파싱 (EUC-KR 등 expat이 못 읽는 인코딩은 직접 디코딩)"""
    m = re.match(rb'<\?xml[^>]*encoding=["\']([\w-]+)["\']', raw.lstrip())
    enc = m.group(1).decode().lower() if m else "utf-8"
    if enc not in ("utf-8", "utf8"):
        text = raw.decode(enc, errors="replace")
        raw = re.sub(r"^\s*<\?xml[^>]*\?>", "", text).encode("utf-8")
    root = ET.fromstring(raw)
    items = []
    for it in root.iter("item"):
        title = (it.findtext("title") or "").strip()
        link = (it.findtext("link") or "").strip()
        if title and link:
            items.append({"title": title, "link": link, "date": (it.findtext("pubDate") or "").strip()})
    return items


def parse_list_html(text, base):
    """RSS가 없을 때 게시판 목록에서 글 링크 추출"""
    items = []
    for m in re.finditer(r'<a[^>]+href="([^"]*(?:view|View)[^"]*)"[^>]*>(.*?)</a>', text, re.S):
        title = re.sub(r"<[^>]+>|\s+", " ", m.group(2)).strip()
        if len(title) >= 8:
            items.append({"title": html.unescape(title), "link": urljoin(base, html.unescape(m.group(1))), "date": ""})
    return items


async def fetch_notices(client, sources):
    for url in sources:
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            head = resp.content[:2000]
            items = parse_rss(resp.content) if b"<rss" in head or b"<item" in resp.content else parse_list_html(resp.text, url)
            log.info("%s → %d건", url, len(items))
            if items:
                return items
        except Exception as e:
            log.warning("%s 조회 실패: %s", url, e)
    return None


def build_message(item, icon, label):
    lines = [f"{icon} <b>{label}</b>", "", f"<b>{html.escape(item['title'])}</b>"]
    if item["date"]:
        lines.append(f"게시: {html.escape(item['date'][:25])}")
    lines += ["", f'🔗 <a href="{html.escape(item["link"])}">원문</a>']
    if re.search(r"업데이트|패치|취약점", item["title"]):
        lines.append("→ 사내 사용 제품이면 패치 일정 확인")
    return "\n".join(lines)


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="전송하지 않고 출력만 (상태 저장 안 함)")
    parser.add_argument("--latest", type=int, default=0, help="이미 본 글이어도 피드별 최신 N건을 다시 전송")
    args = parser.parse_args()

    state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
    if "seen" in state:  # 예전 형식(KISA만) → 피드별 형식
        state = {"kisa": state["seen"]}
    bot = None if args.dry_run else Bot(TOKEN)

    headers = {"User-Agent": "Mozilla/5.0 (kisa-watch)"}
    async with https_only.client(timeout=30, headers=headers, follow_redirects=True) as client:
        for key, (icon, label, sources) in FEEDS.items():
            items = await fetch_notices(client, sources)
            if items is None:
                log.warning("%s 가져오지 못함 (다음 실행에 재시도)", label)
                continue
            first = key not in state
            seen = state.get(key, [])
            new = [it for it in items if it["link"] not in seen]
            # 첫 실행: 최근 몇 건만 보내서 연결 확인, 나머지는 기존 건으로 처리
            to_send = new[:FIRST_RUN_SHOW] if first else new
            if args.latest:
                to_send = items[:args.latest * (5 if key in FILTERED_FEEDS else 1)]
            if key in FILTERED_FEEDS:
                to_send = [it for it in to_send if is_security_news(it["title"])]
                if args.latest:
                    to_send = to_send[:args.latest]
            for it in reversed(to_send):
                text = build_message(it, icon, label)
                if args.dry_run:
                    print(text, "\n" + "-" * 60)
                else:
                    await bot.send_message(chat_id=CHAT_ID, text=text, parse_mode="HTML",
                                           disable_web_page_preview=True)
                    await asyncio.sleep(1)
            log.info("%s 새 글 %d건, 알림 %d건", label, len(new), len(to_send))
            state[key] = (seen + [it["link"] for it in new])[-MAX_SEEN:]
    if not args.dry_run:
        STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    asyncio.run(main())
