# pii-redact-korea-api

한국형 PII(주민번호/휴대폰/이메일/계좌/주소)를 탐지하고 비식별화하는 API 프로토타입.

## 기능
- `POST /scan`: 텍스트 내 PII 엔터티 탐지
- `POST /redact`: `full|partial|token` 마스킹 모드로 비식별화
- `GET /health`: 헬스체크

## 빠른 실행
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app/main.py
```

## 테스트
```bash
source .venv/bin/activate
pytest -q
```

## 예시
```bash
curl -s http://localhost:8017/redact \
  -H 'Content-Type: application/json' \
  -d '{"text":"홍길동 900101-1234567 010-1234-5678 test@example.com", "mode":"partial"}'
```

## 참고
- MVP 단계. 실제 운영 전에는 한국 주소/계좌 패턴 고도화 및 오탐/미탐 평가셋 구축 필요.
