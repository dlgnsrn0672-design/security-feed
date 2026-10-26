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
from datetime import datetime, timedelta, timezone
from pathlib import Path

import telegram

import https_only
import links
from common import CHAT_ID, TOKEN

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


def build_message(cve, score, version, vector, description_ko, kev=None):
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
    ]
    if cwes:
        lines.append(f"유형: {', '.join(cwes)}")
    if kev:
        lines += [""] + kev_lines(kev)
    lines += ["", "<b>설명</b>", html.escape(description_ko), ""]
    sources = [f'<a href="https://nvd.nist.gov/vuln/detail/{cve_id}">NVD</a>']
    if kev:
        sources.append(links.kev(cve_id))
    lines.append(links.line(*sources))
    for url in refs:
        lines.append(f"• {html.escape(url)}")
    return "\n".join(lines)


def build_kev_message(kev, cve, description_ko, already_alerted):
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
    if kev.get("cwes"):
        lines.append(f"유형: {', '.join(kev['cwes'])}")
    lines += [""] + kev_lines(kev)
    lines += ["", "<b>설명</b>", html.escape(description_ko), ""]
    lines.append(links.line(links.kev(cve_id), f'<a href="https://nvd.nist.gov/vuln/detail/{cve_id}">NVD</a>'))
    for url in kev_refs(kev)[:3]:
        lines.append(f"• {html.escape(url)}")
    return "\n".join(lines)


async def send(bot, message, dry_run):
    if dry_run:
        print(message, "\n" + "-" * 60)
        return
    await bot.send_message(
        chat_id=CHAT_ID, text=message,
        parse_mode="HTML", disable_web_page_preview=True,
    )
    await asyncio.sleep(1)


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

    sent = 0
    for cve in cves:
        if cve["id"] in seen or not is_recent(cve, now):
            continue
        scored = best_score(cve)
        if scored is None or scored[0] < MIN_SCORE:
            continue
        score, version, vector = scored
        kev_entry = (kev or {}).get(cve["id"])
        description_ko = await translate_ko(client, english_description(cve))
        await send(bot, build_message(cve, score, version, vector, description_ko, kev_entry), dry_run)
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
        description_ko = await translate_ko(client, entry.get("shortDescription", ""))
        await send(bot, build_kev_message(entry, cve, description_ko, cve_id in seen), dry_run)
        kev_seen.add(cve_id)
        kev_sent += 1

    log.info("CVSS 알림 %d건, KEV 알림 %d건%s", sent, kev_sent, " (dry-run)" if dry_run else "")
    if not dry_run:
        # KEV 조회에 실패했으면 다음에 처음부터 다시 비교하도록 기존 값 유지
        save_state(now, seen, kev_seen if kev is not None or kev_seen else None)


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="한 번만 확인하고 종료")
    parser.add_argument("--dry-run", action="store_true", help="전송하지 않고 출력만 (상태 저장 안 함)")
    args = parser.parse_args()

    bot = telegram.Bot(TOKEN)
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
