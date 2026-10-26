"""알림에 붙이는 '직접 확인' 링크 (사람이 출처에서 다시 확인할 수 있게)

사칭 의심 사이트 자체에는 링크를 걸지 않고, 대신 분석해 주는 조회 사이트로 연결
"""
import html
from urllib.parse import quote


def _a(url, label):
    return f'<a href="{html.escape(url)}">{label}</a>'


def line(*links):
    return "🔎 직접 확인: " + " · ".join(links)


def domain_intel(domain):
    """사칭 의심 도메인: 접속하지 않고 평판·스크린샷·인증서 기록 확인"""
    d = quote(domain)
    return line(_a(f"https://www.virustotal.com/gui/domain/{d}", "VirusTotal"),
                _a(f"https://urlscan.io/search/#domain:{d}", "urlscan(스크린샷)"),
                _a(f"https://crt.sh/?q={d}", "인증서 기록(crt.sh)"))


def cert_log(domain):
    return line(_a(f"https://crt.sh/?q={quote(domain)}", "인증서 기록(crt.sh)"))


def dns_lookup(name):
    return line(_a(f"https://dns.google/query?name={quote(name)}&rr_type=ANY", "DNS 조회(Google)"),
                _a(f"https://crt.sh/?q={quote(name)}", "인증서 기록(crt.sh)"))


def ip_intel(ip):
    return line(_a(f"https://internetdb.shodan.io/{ip}", "InternetDB(원본 데이터)"),
                _a(f"https://www.shodan.io/host/{ip}", "Shodan"))


def domain_registry(domain):
    return line(_a(f"https://lookup.icann.org/en/lookup?name={quote(domain)}", "등록 정보(ICANN 조회)"))


def ssl_check(host):
    # hideResults=on: SSL Labs 공개 목록에 결과를 올리지 않음
    return line(_a(f"https://www.ssllabs.com/ssltest/analyze.html?d={quote(host)}&hideResults=on", "SSL Labs"),
                _a(f"https://crt.sh/?q={quote(host)}", "인증서 기록(crt.sh)"))


def kev(cve_id):
    return _a(f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={quote(cve_id)}",
              "CISA KEV")


def ransomware(group):
    links = [_a("https://www.ransomware.live/", "ransomware.live")]
    if group:
        links.insert(0, _a(f"https://www.ransomware.live/group/{quote(group.lower())}", f"{html.escape(group)} 그룹 페이지"))
    return line(*links)


def hudsonrock():
    return line(_a("https://www.hudsonrock.com/free-tools", "Hudson Rock 무료 조회"))
