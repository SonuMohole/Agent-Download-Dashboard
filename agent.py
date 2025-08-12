import socket
import time

import requests

SERVER_URL = "http://192.168.1.9:8000/agent_heartbeat"
AGENT_ID = socket.gethostname()  # unique agent ID (hostname)

def send_heartbeat():
    try:
        r = requests.post(SERVER_URL, json={"agent_id": AGENT_ID})
        if r.status_code == 200:
            print("Heartbeat sent successfully")
        else:
            print(f"Heartbeat failed: {r.status_code}")
    except Exception as e:
        print(f"Error sending heartbeat: {e}")

if __name__ == "__main__":
    while True:
        send_heartbeat()
        time.sleep(1)  # 5 minutes
