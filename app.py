from flask import Flask, render_template, send_file
from flask_socketio import SocketIO
from flask_cors import CORS
import threading
import time
from capture import start_capture, packet_queue, lock
from detector import analyze, alerts
from report import generate_report

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

stats = {"TCP": 0, "UDP": 0, "ARP": 0, "DNS": 0, "OTHER": 0}

def broadcast_loop():
    last_index = 0
    while True:
        time.sleep(0.5)
        with lock:
            new_packets = packet_queue[last_index:]
            last_index = len(packet_queue)
        for pkt in new_packets:
            ptype = pkt["type"]
            if ptype in stats:
                stats[ptype] += 1
            else:
                stats["OTHER"] += 1
            alert = analyze(pkt)
            socketio.emit("packet", pkt)
            socketio.emit("stats", stats)
            if alert:
                socketio.emit("alert", alert)
        if alerts:
            socketio.emit("alerts_list", alerts[-20:])

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/report")
def download_report():
    path = generate_report()
    return send_file(path, as_attachment=True)

if __name__ == "__main__":
    capture_thread = threading.Thread(
        target=start_capture, args=("ens33",), daemon=True
    )
    capture_thread.start()
    broadcast_thread = threading.Thread(target=broadcast_loop, daemon=True)
    broadcast_thread.start()
    socketio.run(app, host="0.0.0.0", port=5000, debug=False)
