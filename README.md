# security-feed

보안 위협 정보를 텔레그램으로 받는 알림 봇입니다.

| 알림 | 출처 | 조건 |
|---|---|---|
| CVE | NVD | CVSS 9.0 이상, 공개 30일 이내 (DeepL 키가 있으면 한국어 번역) |
| KEV | CISA Known Exploited Vulnerabilities | 실제 악용이 확인된 취약점 신규 등록 (점수 무관) |
| KISA 보안공지 | 보호나라 RSS | 새 글 |
| 보안뉴스 | 보안뉴스 RSS | 새 기사 |

외부 예약 서비스가 5분마다 `feed.yml`을 실행하고, GitHub 예약 실행(10분)은 예비로 둡니다.
모든 통신은 HTTPS로만 하고 평문 요청은 차단합니다.

## 설정 (Settings → Secrets and variables → Actions)
- `TELEGRAM_TOKEN`: 봇 토큰
- `TELEGRAM_CHAT_ID`: 알림 받을 채팅 ID
- `NVD_API_KEY` (선택), `DEEPL_API_KEY` (선택)
