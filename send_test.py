"""설정된 채팅방으로 시험 메시지 전송 (채팅 ID 변경 후 확인용)

MESSAGE가 있으면 그 내용을, ARTICLE_URL이 있으면 기사 제목·요약을 읽어 뉴스 알림 형식으로 한 번 보냄 (수동 공유용)
DRY_RUN=true면 보내지 않고 출력만
"""
import asyncio
import html
import os
import re

import https_only
import telegram


def meta(page, name):
    """og:title 같은 메타 태그 값"""
    for pattern in (rf'<meta[^>]+(?:property|name)=["\']{name}["\'][^>]+content=["\']([^"\']*)',
                    rf'<meta[^>]+content=["\']([^"\']*)["\'][^>]+(?:property|name)=["\']{name}["\']'):
        m = re.search(pattern, page, re.I)
        if m:
            return html.unescape(m.group(1)).strip()
    return ""


async def article_message(url):
    async with https_only.client(timeout=30, follow_redirects=True,
                                 headers={"User-Agent": "Mozilla/5.0 (security-feed)"}) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        page = resp.text
    title = meta(page, "og:title")
    if not title:
        m = re.search(r"<title[^>]*>(.*?)</title>", page, re.S | re.I)
        title = html.unescape(m.group(1)).strip() if m else url
    summary = meta(page, "og:description") or meta(page, "description")
    site = meta(page, "og:site_name")
    lines = ["📰 <b>보안 뉴스</b>" + (f" ({html.escape(site)})" if site else ""), "", f"<b>{html.escape(title)}</b>"]
    if summary:
        lines += ["", html.escape(summary[:300]) + ("…" if len(summary) > 300 else "")]
    lines += ["", f'🔗 <a href="{html.escape(url)}">원문</a>']
    return "\n".join(lines)


async def main():
    token = (os.getenv("TELEGRAM_TOKEN") or "").strip()
    chat_id = (os.getenv("TELEGRAM_CHAT_ID") or "").strip()
    if not token or not chat_id:
        raise SystemExit("TELEGRAM_TOKEN / TELEGRAM_CHAT_ID 미설정")
    message = (os.getenv("MESSAGE") or "").strip().replace("\\n", "\n")
    url = (os.getenv("ARTICLE_URL") or "").strip()
    if url:
        message = await article_message(url)
    if (os.getenv("DRY_RUN") or "").lower() == "true":
        print(message or "(시험 메시지)")
        return
    if message:
        await telegram.Bot(token).send_message(chat_id=chat_id, text=message, parse_mode="HTML",
                                               disable_web_page_preview=True)
    else:
        await telegram.Bot(token).send_message(
            chat_id=chat_id, text="✅ 시험 메시지\n이 방으로 CVE·KEV·KISA·보안뉴스 알림이 옵니다.")
    print("전송 성공")


if __name__ == "__main__":
    asyncio.run(main())
