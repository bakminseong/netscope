from fpdf import FPDF
import time
from detector import alerts

def generate_report():
    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 15, "NetScope Security Report", ln=True, align="C")

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 8, f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
    pdf.ln(5)

    pdf.set_draw_color(200, 200, 200)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(8)

    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 10, "Summary", ln=True)

    high = sum(1 for a in alerts if a["level"] == "HIGH")
    medium = sum(1 for a in alerts if a["level"] == "MEDIUM")

    pdf.set_font("Helvetica", "", 11)
    pdf.set_fill_color(245, 245, 245)
    pdf.cell(90, 9, f"  Total Alerts: {len(alerts)}", ln=False, fill=True)
    pdf.cell(90, 9, f"  HIGH: {high}  |  MEDIUM: {medium}", ln=True, fill=True)
    pdf.ln(6)

    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 10, "Detected Threats", ln=True)
    pdf.ln(2)

    LEVEL_MAP = {"HIGH": "HIGH", "MEDIUM": "MEDIUM"}
    TYPE_MAP = {
        "ARP 스푸핑 의심": "ARP Spoofing Detected",
        "포트스캔 의심": "Port Scan Detected",
        "의심 DNS 쿼리": "Suspicious DNS Query"
    }

    if not alerts:
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(80, 160, 80)
        pdf.cell(0, 9, "  No threats detected.", ln=True)
    else:
        for a in alerts:
            alert_type = TYPE_MAP.get(a["type"], a["type"])
            detail = a["detail"]
            # 한글 제거 - 숫자/영문/기호만 남기기
            detail_safe = ""
            for ch in detail:
                if ord(ch) < 256:
                    detail_safe += ch
                else:
                    detail_safe += "?"

            if a["level"] == "HIGH":
                pdf.set_fill_color(255, 235, 235)
                pdf.set_text_color(200, 30, 30)
            else:
                pdf.set_fill_color(255, 248, 225)
                pdf.set_text_color(180, 120, 0)

            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 8, f"  [{a['level']}] {a['time']}  -  {alert_type}", ln=True, fill=True)

            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(60, 60, 60)
            pdf.set_fill_color(250, 250, 250)
            pdf.cell(0, 7, f"    {detail_safe}", ln=True, fill=True)
            pdf.ln(1)

    pdf.ln(10)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(0, 8, "NetScope - Real-time Network Security Monitor", ln=True, align="C")

    path = f"/home/minseong/netscope/report_{time.strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(path)
    return path
