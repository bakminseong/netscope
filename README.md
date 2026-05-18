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

## 요구 사항
- Linux (Ubuntu / Kali 권장)
- Python 3.x
- 네트워크 캡처를 위해 sudo 권한 필요

## 설치 방법

### 1. 레포지토리 클론
git clone https://github.com/bakminseong/netscope.git
cd netscope

### 2. 패키지 설치
sudo pip install scapy flask flask-socketio flask-cors eventlet fpdf2 --break-system-packages

### 3. 네트워크 인터페이스 확인
ip a
# 본인 인터페이스 이름 확인 (예: eth0, ens33)

### 4. capture.py 인터페이스 수정
nano capture.py
# 마지막 줄 interface="ens33" 을 본인 인터페이스로 변경

### 5. 실행
sudo python3 app.py

### 6. 브라우저 접속
http://[서버IP]:5000

## 탐지 가능 위협
| 위협 유형 | 탐지 방법 | 위험도 |
|---|---|---|
| 포트스캔 | 5초 내 10개 이상 포트 접근 감지 | MEDIUM |
| ARP 스푸핑 | MAC 주소 변경 감지 | HIGH |
| 의심 DNS | 악성 키워드 도메인 접근 감지 | MEDIUM |

## 포트스캔 탐지 테스트
nmap 설치 후 아래 명령어로 테스트 가능
sudo apt install nmap -y
sudo nmap -sS [대상IP]
