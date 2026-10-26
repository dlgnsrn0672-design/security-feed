"""평문(http) 통신을 막는 httpx 클라이언트

https가 아닌 주소로의 요청은 리다이렉트 포함 전부 차단
"""
import httpx


class PlaintextBlocked(httpx.RequestError):
    pass


async def _require_https(request):
    if request.url.scheme != "https":
        raise PlaintextBlocked(f"평문 요청 차단: {request.url}", request=request)


def client(**kwargs):
    hooks = kwargs.pop("event_hooks", {})
    hooks.setdefault("request", []).insert(0, _require_https)
    return httpx.AsyncClient(event_hooks=hooks, **kwargs)
