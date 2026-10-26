"""설정된 채팅방으로 시험 메시지 전송 (채팅 ID 변경 후 확인용)"""
import asyncio
import os

import telegram


async def main():
    token = (os.getenv("TELEGRAM_TOKEN") or "").strip()
    chat_id = (os.getenv("TELEGRAM_CHAT_ID") or "").strip()
    if not token or not chat_id:
        raise SystemExit("TELEGRAM_TOKEN / TELEGRAM_CHAT_ID 미설정")
    await telegram.Bot(token).send_message(
        chat_id=chat_id, text="✅ 시험 메시지\n이 방으로 CVE·KEV·KISA·보안뉴스 알림이 옵니다.")
    print("전송 성공")


asyncio.run(main())
