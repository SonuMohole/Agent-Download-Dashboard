import socket
import time

import requests

SERVER_URL = "http://192.168.1.9:8000/agent_heartbeat"
AGENT_ID = socket.gethostname()  # Unique agent ID (hostname)
HOSTNAME = socket.gethostname()  # Explicit hostname to send

def send_heartbeat():
    try:
        r = requests.post(SERVER_URL, json={
            "agent_id": AGENT_ID,
            "hostname": HOSTNAME
        })
        if r.status_code == 200:
            print(f"[{time.strftime('%H:%M:%S')}] Heartbeat sent")
        else:
            print(f"Heartbeat failed: {r.status_code}")
    except Exception as e:
        print(f"Error sending heartbeat: {e}")

if __name__ == "__main__":
    while True:
        send_heartbeat()
        time.sleep(5)  # send heartbeat every 5 seconds
