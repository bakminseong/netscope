# 🛡 NetScope - Real-time Network Security Monitor

실시간 네트워크 트래픽을 캡처하고 보안 위협을 자동 탐지하는 모니터링 도구

## 주요 기능
- 실시간 패킷 캡처 및 프로토콜 분류 (TCP/UDP/ARP/DNS)
- 위협 자동 탐지 (포트스캔 / ARP 스푸핑 / 의심 DNS)
- 웹 기반 실시간 대시보드 시각화
- 탐지 결과 PDF 리포트 자동 생성

## 기술 스택
- Python, Scapy, Flask, Flask-SocketIO
- HTML, JavaScript, Chart.js
- fpdf2

## 실행 방법
```bash
sudo python3 app.py
```
브라우저에서 `http://[서버IP]:5000` 접속

## 탐지 가능 위협
| 위협 유형 | 탐지 방법 | 위험도 |
|---|---|---|
| 포트스캔 | 5초 내 10개 이상 포트 접근 감지 | MEDIUM |
| ARP 스푸핑 | MAC 주소 변경 감지 | HIGH |
| 의심 DNS | 악성 키워드 도메인 접근 감지 | MEDIUM |
