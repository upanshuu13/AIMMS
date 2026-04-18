import time
import threading
import requests
from scapy.all import sniff, IP, TCP, UDP

# ─── CONFIG ───────────────────────────────────────────────────────────────
API_URL       = "http://localhost:3000/api/network-event"
BATCH_SIZE    = 20        # increased batch size
BATCH_TIMEOUT = 2.0

# 👉 IMPORTANT: Replace with your VM IP (run: hostname -I)
IGNORED_IPS = {"127.0.0.1", "10.57.92.252"}

# Only monitor important ports
MONITORED_PORTS = {22, 80, 443}

# ─── SHARED STATE ─────────────────────────────────────────────────────────
batch = []
batch_lock = threading.Lock()
last_flush = time.time()

# ─── PACKET HANDLER ───────────────────────────────────────────────────────
def handle_packet(pkt):
    global last_flush

    if not pkt.haslayer(IP):
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    # Ignore self traffic
    if src_ip in IGNORED_IPS:
        return

    protocol = "OTHER"
    dst_port = None

    if pkt.haslayer(TCP):
        protocol = "TCP"
        dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        protocol = "UDP"
        dst_port = pkt[UDP].dport

    # Filter only important ports
    if dst_port not in MONITORED_PORTS:
        return

    event = {
        "source_ip": src_ip,
        "dest_ip": dst_ip,
        "port": dst_port,
        "protocol": protocol,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    with batch_lock:
        batch.append(event)

        should_flush = (
            len(batch) >= BATCH_SIZE or
            (time.time() - last_flush) >= BATCH_TIMEOUT
        )

    if should_flush:
        flush_batch()

# ─── BATCH SENDER ─────────────────────────────────────────────────────────
def flush_batch():
    global last_flush

    with batch_lock:
        if not batch:
            return
        to_send = batch.copy()
        batch.clear()
        last_flush = time.time()

    try:
        resp = requests.post(
            API_URL,
            json={"events": to_send},
            timeout=3
        )
        print(f"[sniffer] sent {len(to_send)} events → {resp.status_code}")

    except requests.exceptions.ConnectionError:
        print("[sniffer] ERROR: cannot reach API. Is Node running?")
    except Exception as e:
        print(f"[sniffer] ERROR: {e}")

# ─── PERIODIC FLUSH ───────────────────────────────────────────────────────
def flush_worker():
    while True:
        time.sleep(BATCH_TIMEOUT)
        flush_batch()

# ─── MAIN ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("[sniffer] AIMMS Packet Sniffer Started")
    print(f"[sniffer] sending data → {API_URL}")
    print("[sniffer] filtering ports → 22, 80, 443")
    print("[sniffer] press Ctrl+C to stop\n")

    t = threading.Thread(target=flush_worker, daemon=True)
    t.start()

    sniff(
        filter="tcp or udp",
        prn=handle_packet,
        store=False
    )