import os
import socket

from dotenv import load_dotenv

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
