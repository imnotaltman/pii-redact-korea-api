from app.main import app


def test_scan_detects_korean_pii():
    client = app.test_client()
    text = "홍길동 900101-1234567 연락처 010-1234-5678 이메일 test@example.com"
    resp = client.post('/scan', json={'text': text})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body['count'] >= 3


def test_redact_partial():
    client = app.test_client()
    text = "계좌 110-123-123456 주민번호 9001011234567"
    resp = client.post('/redact', json={'text': text, 'mode': 'partial'})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body['count'] >= 2
    assert '*' in body['redacted_text']
