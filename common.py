import asyncio
import os
import re
import socket

import telegram
from dotenv import load_dotenv
from telegram.error import ChatMigrated, NetworkError, RetryAfter, TimedOut
from telegram.request import HTTPXRequest

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

# 사내 사용 제품 (쉼표 구분). 공개 저장소라 목록은 코드가 아니라 GitHub Secret PRODUCT_KEYWORDS에만 둠
PRODUCT_KEYWORDS = [k.strip().lower() for k in (os.getenv("PRODUCT_KEYWORDS") or "").split(",") if k.strip()]


def product_hits(text):
    """글에 나오는 사내 사용 제품 (단어 단위로 비교: 'api'가 'rapid'에 걸리지 않게)"""
    low = (text or "").lower()
    return [k for k in PRODUCT_KEYWORDS if re.search(rf"(?<![a-z0-9]){re.escape(k)}(?![a-z0-9])", low)]


def hide_products(text):
    """공개 저장소 로그에 출력할 때 사내 제품명을 가림 (dry-run 출력용)"""
    text = re.sub(r"(🏢 <b>사내 사용 제품 관련</b>: ).*", r"\1(공개 로그라 숨김)", text)
    for k in PRODUCT_KEYWORDS:
        text = re.sub(rf"(?<![a-z0-9]){re.escape(k)}(?![a-z0-9])", "***", text, flags=re.I)
    return text


def product_line(text):
    hits = product_hits(text)
    return f"🏢 <b>사내 사용 제품 관련</b>: {', '.join(hits)}" if hits else ""


class Bot(telegram.Bot):
    """채팅방이 슈퍼그룹으로 바뀌어 채팅 ID가 달라져도 새 ID로 다시 보냄

    텔레그램은 방 설정(권한·관리자 등)을 바꾸면 그룹을 슈퍼그룹으로 바꾸고
    예전 ID로 보내면 새 ID를 알려주며 거절함 → 그 ID로 재전송하고 방에 안내를 남김
    한꺼번에 많이 보내 전송 제한(flood control)에 걸리면 알려준 시간만큼 기다렸다 다시 보냄
    연결 자체가 안 되면 잠시 뒤 다시 보냄. 응답만 늦은 경우(시간 초과)는 이미 전달됐을 수 있어
    한 번만 다시 보냄 (여러 번 재전송하면 같은 메시지가 중복으로 올라옴)
    """
    _notified = False

    def __init__(self, token, *args, **kwargs):
        # 기본 응답 대기(5초)가 짧아 긴 메시지가 전달되고도 시간 초과로 처리되는 일이 있어 넉넉히
        kwargs.setdefault("request", HTTPXRequest(connect_timeout=10, read_timeout=30, write_timeout=30))
        super().__init__(token, *args, **kwargs)

    async def _send(self, chat_id, *args, **kwargs):
        timed_out = False
        for _ in range(5):
            try:
                return await super().send_message(chat_id, *args, **kwargs)
            except RetryAfter as e:
                wait = e.retry_after
                wait = wait.total_seconds() if hasattr(wait, "total_seconds") else wait
                print(f"⏳ 텔레그램 전송 제한: {wait}초 기다린 뒤 다시 보냄")
                await asyncio.sleep(wait + 1)
            except TimedOut:
                if timed_out:
                    raise
                timed_out = True
                print("⏳ 텔레그램 응답 시간 초과: 10초 뒤 한 번만 다시 보냄")
                await asyncio.sleep(10)
            except NetworkError as e:
                # 연결 실패 등 전송 전 단계 오류 → 메시지가 가지 않았으니 다시 보내도 중복 없음
                print(f"⏳ 텔레그램 연결 문제({e}): 5초 뒤 다시 보냄")
                await asyncio.sleep(5)
        return await super().send_message(chat_id, *args, **kwargs)

    async def send_message(self, chat_id, *args, **kwargs):
        try:
            return await self._send(chat_id, *args, **kwargs)
        except ChatMigrated as e:
            new_id = e.new_chat_id
            print(f"⚠️ 채팅 ID 변경: {chat_id} → {new_id} (Secrets의 채팅 ID를 새 값으로 바꿔 주세요)")
            result = await self._send(new_id, *args, **kwargs)
            if not Bot._notified:
                Bot._notified = True
                await self._send(
                    new_id, f"ℹ️ 이 방의 채팅 ID가 바뀌었습니다 (슈퍼그룹 전환).\n"
                            f"알림은 새 ID로 계속 보내고 있지만, GitHub Secrets의 채팅 ID를 아래 값으로 바꿔 주세요.\n"
                            f"{new_id}")
            return result
