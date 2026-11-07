"""NVD의 Critical(기본 9.0 이상) 취약점과 CISA KEV(실제 악용 확인) 신규 등록 건을
주기적으로 확인해서 한국어로 텔레그램 알림

실행:  python cve_alert.py            (계속 돌면서 감시)
       python cve_alert.py --once     (한 번만 확인)
       python cve_alert.py --dry-run  (텔레그램 전송 없이 터미널에 출력만)
"""
import argparse
import asyncio
import html
import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path


import https_only
import links
from common import CHAT_ID, TOKEN, Bot

# CVE·KISA 알림은 전용 봇이 있으면 그쪽으로 (없으면 기본 봇)
TOKEN = (os.getenv("CVE_TELEGRAM_TOKEN") or "").strip() or TOKEN
CHAT_ID = (os.getenv("CVE_TELEGRAM_CHAT_ID") or "").strip() or CHAT_ID

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URLS = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    # CISA 사이트 장애 시 공식 GitHub 미러
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
)
STATE_FILE = Path(__file__).with_name("state.json")
MAX_SEEN = 5000

NVD_API_KEY = os.getenv("NVD_API_KEY") or None
MIN_SCORE = float(os.getenv("MIN_CVSS_SCORE", "9.0"))
POLL_MINUTES = int(os.getenv("POLL_MINUTES", "15"))
LOOKBACK_HOURS = int(os.getenv("FIRST_RUN_LOOKBACK_HOURS", "24"))
MAX_AGE_DAYS = int(os.getenv("MAX_CVE_AGE_DAYS", "30"))
DEEPL_API_KEY = os.getenv("DEEPL_API_KEY") or None
# 처음 실행할 때 KEV 목록 중 최근 며칠 등록분만 알림 (나머지 1700여 건은 기존 건으로 처리)
KEV_FIRST_RUN_DAYS = int(os.getenv("KEV_FIRST_RUN_DAYS", "3"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)
log = logging.getLogger("cve_alert")


def load_state():
    """last_check, seen(CVSS 알림 보낸 CVE), kev_seen(KEV 알림 보낸 CVE, 처음이면 None)"""
    if STATE_FILE.exists():
        state = json.loads(STATE_FILE.read_text())
        return datetime.fromisoformat(state["last_check"]), state["seen"], state.get("kev_seen")
    return datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS), [], None


def save_state(last_check, seen, kev_seen):
    state = {"last_check": last_check.isoformat(), "seen": seen[-MAX_SEEN:]}
    if kev_seen is not None:
        # KEV는 전체 목록과 비교해야 하므로 자르지 않음
        state["kev_seen"] = sorted(kev_seen)
    STATE_FILE.write_text(json.dumps(state, indent=2))


def nvd_time(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


async def fetch_critical(client, start, end):
    """start~end 사이에 등록/수정된 Critical CVE 목록 (v3, v4 둘 다 조회)"""
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    results = {}
    for severity_param in ("cvssV3Severity", "cvssV4Severity"):
        index = 0
        while True:
            params = {
                "lastModStartDate": nvd_time(start),
                "lastModEndDate": nvd_time(end),
                severity_param: "CRITICAL",
                "startIndex": index,
            }
            resp = await client.get(NVD_URL, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            for item in data["vulnerabilities"]:
                cve = item["cve"]
                results[cve["id"]] = cve
            index += data["resultsPerPage"]
            if index >= data["totalResults"] or data["resultsPerPage"] == 0:
                break
        # API 키 없으면 30초에 5번 제한
        await asyncio.sleep(1 if NVD_API_KEY else 6)
    return list(results.values())


async def fetch_kev(client):
    """CISA KEV 전체 목록 {CVE ID: 항목}. 실패하면 None"""
    for url in KEV_URLS:
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            return {v["cveID"]: v for v in resp.json()["vulnerabilities"]}
        except Exception as e:
            log.warning("KEV 조회 실패 (%s): %s", url, e)
    return None


async def fetch_cve(client, cve_id):
    """KEV 알림에 점수를 붙이기 위해 NVD에서 CVE 하나 조회. 실패하면 None"""
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    try:
        resp = await client.get(NVD_URL, params={"cveId": cve_id}, headers=headers)
        resp.raise_for_status()
        items = resp.json()["vulnerabilities"]
        return items[0]["cve"] if items else None
    except Exception as e:
        log.warning("NVD %s 조회 실패: %s", cve_id, e)
        return None
    finally:
        await asyncio.sleep(1 if NVD_API_KEY else 6)


def best_score(cve):
    """가장 높은 CVSS 점수와 그 버전/벡터"""
    best = None
    for key, version in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        for metric in cve.get("metrics", {}).get(key, []):
            data = metric["cvssData"]
            if best is None or data["baseScore"] > best[0]:
                best = (data["baseScore"], version, data["vectorString"])
    return best


def english_description(cve):
    for desc in cve.get("descriptions", []):
        if desc["lang"] == "en":
            return desc["value"]
    return ""


def is_recent(cve, now):
    """수정만 된 옛날 CVE는 제외하고 최근 공개된 것만"""
    published = datetime.fromisoformat(cve["published"]).replace(tzinfo=timezone.utc)
    return now - published <= timedelta(days=MAX_AGE_DAYS)


async def translate_ko(client, text):
    if not text:
        return "(설명 없음)"
    if not DEEPL_API_KEY:
        return text
    # 무료 키는 끝이 :fx 이고 주소가 다름
    host = "api-free.deepl.com" if DEEPL_API_KEY.endswith(":fx") else "api.deepl.com"
    try:
        resp = await client.post(
            f"https://{host}/v2/translate",
            headers={"Authorization": f"DeepL-Auth-Key {DEEPL_API_KEY}"},
            json={"text": [text], "source_lang": "EN", "target_lang": "KO"},
        )
        resp.raise_for_status()
        return resp.json()["translations"][0]["text"]
    except Exception as e:
        log.warning("번역 실패, 원문 사용: %s", e)
        return text


RANSOMWARE_KO = {"Known": "사용 확인됨", "Unknown": "확인되지 않음"}


EPSS_URL = "https://api.first.org/data/v1/epss"


async def fetch_epss(client, cve_id):
    """(악용 확률, 백분위) — 앞으로 30일 안에 실제 악용될 확률 (FIRST EPSS). 없거나 실패면 None"""
    try:
        resp = await client.get(EPSS_URL, params={"cve": cve_id})
        resp.raise_for_status()
        data = resp.json().get("data") or []
        if data:
            return float(data[0]["epss"]), float(data[0]["percentile"])
    except Exception as e:
        log.warning("EPSS %s 조회 실패: %s", cve_id, e)
    return None


def epss_line(epss):
    if not epss:
        return "EPSS: 아직 산정 전 (신규 취약점은 하루 정도 걸림)"
    prob, pct = epss
    icon = "🔥" if prob >= 0.5 else "🔴" if prob >= 0.1 else "🟠" if prob >= 0.01 else "🟢"
    level = ("매우 높음" if prob >= 0.5 else "높음" if prob >= 0.1 else "보통" if prob >= 0.01 else "낮음")
    shown = f"{prob * 100:.2f}" if prob < 0.01 else f"{prob * 100:.1f}"
    return (f"{icon} EPSS 악용 확률: <b>{shown}%</b> ({level}, 상위 {max(0.1, (1 - pct) * 100):.1f}%)"
            " — 30일 내 실제 공격 예측")


def kev_lines(kev):
    """판단에 필요한 실제 악용 정보"""
    lines = [
        "⚠️ <b>실제 공격에 악용 중 (CISA KEV 등록)</b>",
        "→ 해당 제품을 쓰고 있다면 점수와 상관없이 즉시 패치/완화 조치 필요",
        f"KEV 등록일: {kev['dateAdded']} / CISA 조치기한: {kev['dueDate']}",
    ]
    ransomware = kev.get("knownRansomwareCampaignUse", "Unknown")
    if ransomware == "Known":
        lines.append("랜섬웨어 캠페인 사용: <b>사용 확인됨</b> 🔥")
    else:
        lines.append(f"랜섬웨어 캠페인 사용: {RANSOMWARE_KO.get(ransomware, ransomware)}")
    if kev.get("forensicTriage") == "Yes":
        lines.append("침해 흔적 점검(포렌식) 권고: <b>예</b> — 패치 전에 이미 뚫렸는지도 확인")
    return lines


def kev_refs(kev):
    """KEV 비고란의 벤더 공지 링크 (CISA 지침/NVD 링크 제외)"""
    urls = []
    for part in kev.get("notes", "").split(";"):
        part = part.strip()
        url = part[part.find("http"):] if "http" in part else ""
        if url and "cisa.gov" not in url and "nvd.nist.gov" not in url:
            urls.append(url)
    return urls


def build_message(cve, score, version, vector, description_ko, kev=None, epss=None):
    cve_id = cve["id"]
    published = cve.get("published", "")[:10]
    refs = [r["url"] for r in cve.get("references", [])][:3]
    cwes = sorted({
        d["value"] for w in cve.get("weaknesses", []) for d in w["description"]
        if d["value"].startswith("CWE-")
    })

    lines = [
        f"🚨 <b>CVSS {score} 취약점 발견</b>",
        "",
        f"<b>{html.escape(cve_id)}</b>",
        f"점수: <b>{score}</b> (CVSS v{version})",
        f"벡터: <code>{html.escape(vector)}</code>",
        f"공개일: {published}",
        epss_line(epss),
    ]
    if cwes:
        lines.append(f"유형: {', '.join(cwes)}")
    if kev:
        lines += [""] + kev_lines(kev)
    lines += ["", "<b>설명</b>", html.escape(description_ko), ""]
    sources = [f'<a href="https://nvd.nist.gov/vuln/detail/{cve_id}">NVD</a>',
               '<a href="https://www.first.org/epss/data_stats">EPSS</a>']
    if kev:
        sources.append(links.kev(cve_id))
    lines.append(links.line(*sources))
    for url in refs:
        lines.append(f"• {html.escape(url)}")
    return "\n".join(lines)


def build_kev_message(kev, cve, description_ko, already_alerted, epss=None):
    cve_id = kev["cveID"]
    title = "🔴 <b>실제 악용 취약점 신규 등록 (CISA KEV)</b>"
    lines = [title, ""]
    if already_alerted:
        lines += ["ℹ️ 앞서 CVSS 알림을 보낸 취약점이 <b>실제 공격에 쓰이는 것으로 확인</b>되었습니다", ""]
    lines += [
        f"<b>{html.escape(cve_id)}</b>",
        f"제품: {html.escape(kev['vendorProject'])} {html.escape(kev['product'])}",
        f"이름: {html.escape(kev['vulnerabilityName'])}",
    ]
    scored = best_score(cve) if cve else None
    if scored:
        score, version, vector = scored
        lines.append(f"점수: <b>{score}</b> (CVSS v{version})")
        lines.append(f"벡터: <code>{html.escape(vector)}</code>")
    else:
        lines.append("점수: NVD 미산정 (점수가 없어도 실제 악용 중이므로 우선 대응)")
    lines.append(epss_line(epss))
    if kev.get("cwes"):
        lines.append(f"유형: {', '.join(kev['cwes'])}")
    lines += [""] + kev_lines(kev)
    lines += ["", "<b>설명</b>", html.escape(description_ko), ""]
    lines.append(links.line(links.kev(cve_id), f'<a href="https://nvd.nist.gov/vuln/detail/{cve_id}">NVD</a>'))
    for url in kev_refs(kev)[:3]:
        lines.append(f"• {html.escape(url)}")
    return "\n".join(lines)


STOP_WORDS = {"could", "is", "are", "contains", "through", "versions", "version", "allows", "and", "before", "prior"}


def product_key(cve):
    """설명 앞부분의 제품명 (예: 'IBM API Connect 10.0.8 through ...' → 'IBM API Connect')"""
    words = []
    for w in english_description(cve).split():
        w = w.strip(",;:()-–")
        if not w or re.search(r"\d", w) or w.lower() in STOP_WORDS or len(words) == 5:
            break
        words.append(w)
    return " ".join(words) if len(words) >= 2 else None


def impact(cve):
    """설명에서 영향 부분만 (버전 나열 뒤 'could allow ...' 등)"""
    desc = english_description(cve)
    m = re.search(r"\b(could allow|allows?|is vulnerable|are vulnerable|contains|uses|could)\b", desc)
    return (desc[m.start():] if m else desc)[:160].strip()


def epss_badge(epss):
    if not epss:
        return "EPSS 산정 전"
    prob = epss[0]
    icon = "🔥" if prob >= 0.5 else "🔴" if prob >= 0.1 else "🟠" if prob >= 0.01 else "🟢"
    return f"{icon} EPSS {prob * 100:.1f}%"


def build_digest(entries, kev_ids=(), per_msg=15):
    """entries: [(cve, score, 한국어 요약, epss)] → 이번 실행 새 취약점을 모은 메시지 (15건씩)"""
    entries = sorted(entries, key=lambda e: (product_key(e[0]) or "~", -e[1]))
    pages = (len(entries) + per_msg - 1) // per_msg
    msgs = []
    for i in range(0, len(entries), per_msg):
        lines = [f"🚨 <b>새 Critical 취약점 {len(entries)}건</b> (CVSS {MIN_SCORE} 이상)"
                 + (f" ({i // per_msg + 1}/{pages})" if pages > 1 else ""), ""]
        for cve, score, summary_ko, epss in entries[i:i + per_msg]:
            product = product_key(cve) or ""
            flag = "⚠️<b>실제 악용</b> " if cve["id"] in kev_ids else ""
            lines.append(f'{flag}<b>{score}</b> <a href="https://nvd.nist.gov/vuln/detail/{cve["id"]}">{cve["id"]}</a> '
                         f"{html.escape(product)} · {epss_badge(epss)}")
            lines.append(f"   └ {html.escape(summary_ko[:90])}")
        lines += ["", "→ 사내 사용 제품이 있으면 CVE를 눌러 상세·패치 정보 확인"]
        msgs.append("\n".join(lines))
    return msgs


async def send(bot, message, dry_run):
    if dry_run:
        print(message, "\n" + "-" * 60)
        return
    await bot.send_message(
        chat_id=CHAT_ID, text=message,
        parse_mode="HTML", disable_web_page_preview=True,
    )
    # 단체방은 분당 20건 정도로 전송이 제한되어 간격을 둠
    await asyncio.sleep(3)


async def check_once(bot, client, dry_run):
    last_check, seen, kev_seen = load_state()
    now = datetime.now(timezone.utc)
    # NVD 반영 지연 대비해서 5분 겹치게 조회 (중복은 seen으로 걸러짐)
    start = last_check - timedelta(minutes=5)

    kev = await fetch_kev(client)
    if kev is not None and kev_seen is None:
        # 첫 실행: 최근 등록분만 새 건으로 보고 나머지는 이미 본 것으로 처리
        cutoff = (now - timedelta(days=KEV_FIRST_RUN_DAYS)).date().isoformat()
        kev_seen = [cve_id for cve_id, v in kev.items() if v["dateAdded"] < cutoff]
    kev_seen = set(kev_seen or [])

    cves = await fetch_critical(client, start, now)
    log.info("%s ~ %s: Critical %d건 조회", start.strftime("%m-%d %H:%M"), now.strftime("%m-%d %H:%M"), len(cves))

    sent, kev_sent, done = 0, 0, False
    try:
        sent, kev_sent = await send_new(bot, client, cves, kev, seen, kev_seen, now, dry_run)
        done = True
    finally:
        if not dry_run:
            # 중간에 실패해도 이미 보낸 건은 기록해서 다음 실행에 다시 보내지 않음
            # (조회 기준 시각은 끝까지 성공했을 때만 앞으로)
            save_state(now if done else last_check, seen, kev_seen if kev is not None or kev_seen else None)
    log.info("CVSS 알림 %d건, KEV 알림 %d건%s", sent, kev_sent, " (dry-run)" if dry_run else "")


async def send_new(bot, client, cves, kev, seen, kev_seen, now, dry_run):
    sent = 0
    todo = []
    for cve in cves:
        if cve["id"] in seen or not is_recent(cve, now):
            continue
        scored = best_score(cve)
        if scored is not None and scored[0] >= MIN_SCORE:
            todo.append((cve, scored))

    # 한 번 실행에서 새 건이 여러 개면 한 메시지로 모아서 보냄 (1건이면 아래에서 자세히)
    if len(todo) >= 2:
        sem = asyncio.Semaphore(5)

        async def prepare(cve, scored):
            async with sem:
                summary_ko, epss = await asyncio.gather(translate_ko(client, impact(cve)),
                                                        fetch_epss(client, cve["id"]))
            return cve, scored[0], summary_ko, epss

        entries = await asyncio.gather(*(prepare(cve, scored) for cve, scored in todo))
        for message in build_digest(entries, kev or {}):
            await send(bot, message, dry_run)
        # 실제 악용(KEV) 건은 아래 KEV 알림으로 따로 자세히 한 번 더 감
        for cve, _ in todo:
            seen.append(cve["id"])
        log.info("CVSS 묶음 알림 %d건: %s", len(todo), ", ".join(c["id"] for c, _ in todo))
        sent += len(todo)
        todo = []

    for cve, scored in todo:
        score, version, vector = scored
        kev_entry = (kev or {}).get(cve["id"])
        description_ko, epss = await asyncio.gather(translate_ko(client, english_description(cve)),
                                                    fetch_epss(client, cve["id"]))
        await send(bot, build_message(cve, score, version, vector, description_ko, kev_entry, epss), dry_run)
        log.info("CVSS 알림: %s (%.1f) %s", cve["id"], score, english_description(cve)[:80])
        seen.append(cve["id"])
        if kev_entry:
            # 악용 정보까지 이미 담았으니 KEV 알림은 따로 안 보냄
            kev_seen.add(cve["id"])
        sent += 1

    kev_sent = 0
    for cve_id, entry in sorted((kev or {}).items(), key=lambda kv: kv[1]["dateAdded"]):
        if cve_id in kev_seen:
            continue
        cve = await fetch_cve(client, cve_id)
        description_ko, epss = await asyncio.gather(translate_ko(client, entry.get("shortDescription", "")),
                                                    fetch_epss(client, cve_id))
        await send(bot, build_kev_message(entry, cve, description_ko, cve_id in seen, epss), dry_run)
        log.info("KEV 알림: %s %s", cve_id, entry.get("product", ""))
        kev_seen.add(cve_id)
        kev_sent += 1

    return sent, kev_sent


async def audit(client, keyword, days):
    """최근 Critical CVE 중 keyword가 들어간 것과 이미 알림 보냈는지 출력 (전송·저장 안 함)"""
    _, seen, _ = load_state()
    now = datetime.now(timezone.utc)
    cves = await fetch_critical(client, now - timedelta(days=days), now)
    hits = sorted((c for c in cves if keyword.lower() in english_description(c).lower()), key=lambda c: c["published"])
    log.info("최근 %d일 Critical %d건 중 '%s' %d건 (CVE 번호 기준 중복 없음)", days, len(cves), keyword, len(hits))
    for c in hits:
        scored = best_score(c)
        log.info("%s | 공개 %s | 수정 %s | %s | %s | %s", c["id"], c["published"][:10], c["lastModified"][:10],
                 scored[0] if scored else "-", "알림 보냄" if c["id"] in seen else "안 보냄",
                 english_description(c)[:90])


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="한 번만 확인하고 종료")
    parser.add_argument("--dry-run", action="store_true", help="전송하지 않고 출력만 (상태 저장 안 함)")
    parser.add_argument("--audit", default="", help="이 단어가 들어간 최근 Critical CVE와 알림 여부만 출력")
    parser.add_argument("--audit-days", type=int, default=14)
    args = parser.parse_args()

    if args.audit:
        async with https_only.client(timeout=60) as client:
            await audit(client, args.audit, args.audit_days)
        return
    bot = Bot(TOKEN)
    async with https_only.client(timeout=60) as client:
        while True:
            try:
                await check_once(bot, client, args.dry_run)
            except Exception:
                log.exception("확인 중 오류 (다음 주기에 재시도)")
            if args.once or args.dry_run:
                break
            await asyncio.sleep(POLL_MINUTES * 60)


if __name__ == "__main__":
    asyncio.run(main())
