import os
import socket

import telegram
from dotenv import load_dotenv
from telegram.error import ChatMigrated

load_dotenv()


def force_ipv4():
    """IPv6 연결이 안 되는 환경에서 모든 접속을 IPv4로만 하도록 고정"""
    original = socket.getaddrinfo

    def ipv4_only(host, port, family=0, *args, **kwargs):
        return original(host, port, socket.AF_INET, *args, **kwargs)

    socket.getaddrinfo = ipv4_only


if os.getenv("FORCE_IPV4") == "1":
    force_ipv4()


def require_env(name):
    # 복사할 때 섞여 들어간 공백·줄바꿈 제거
    value = (os.getenv(name) or "").strip()
    if not value:
        raise SystemExit(f".env에 {name} 값이 없습니다")
    return value


TOKEN = require_env("TELEGRAM_TOKEN")
CHAT_ID = require_env("TELEGRAM_CHAT_ID")


class Bot(telegram.Bot):
    """채팅방이 슈퍼그룹으로 바뀌어 채팅 ID가 달라져도 새 ID로 다시 보냄

    텔레그램은 방 설정(권한·관리자 등)을 바꾸면 그룹을 슈퍼그룹으로 바꾸고
    예전 ID로 보내면 새 ID를 알려주며 거절함 → 그 ID로 재전송하고 방에 안내를 남김
    """
    _notified = False

    async def send_message(self, chat_id, *args, **kwargs):
        try:
            return await super().send_message(chat_id, *args, **kwargs)
        except ChatMigrated as e:
            new_id = e.new_chat_id
            print(f"⚠️ 채팅 ID 변경: {chat_id} → {new_id} (Secrets의 채팅 ID를 새 값으로 바꿔 주세요)")
            result = await super().send_message(new_id, *args, **kwargs)
            if not Bot._notified:
                Bot._notified = True
                await super().send_message(
                    new_id, f"ℹ️ 이 방의 채팅 ID가 바뀌었습니다 (슈퍼그룹 전환).\n"
                            f"알림은 새 ID로 계속 보내고 있지만, GitHub Secrets의 채팅 ID를 아래 값으로 바꿔 주세요.\n"
                            f"{new_id}")
            return result
