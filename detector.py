"""Port scan detector: reads a packet capture, flags port scans, and logs them to SQLite."""
import argparse
import sqlite3
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone

from scapy.layers.inet import IP, TCP
from scapy.utils import rdpcap

SYN = 0x02
ACK = 0x10


def get_syns(pcap_path):
    """Return (time, source IP, destination port) for every new connection attempt."""
    syns = []
    for pkt in rdpcap(pcap_path):
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            flags = int(pkt[TCP].flags)
            if flags & SYN and not flags & ACK:  # SYN set, ACK not set = "can I connect?"
                syns.append((float(pkt.time), pkt[IP].src, pkt[TCP].dport))
    return syns

def detect_scans(syns, threshold=20, window=10.0):
    """Flag any source IP that tries `threshold` or more different ports within `window` seconds."""
    recent = defaultdict(deque)         # source IP -> (time, port) attempts inside the window
    port_counts = defaultdict(Counter)  # source IP -> how many times each port shows up in the window
    alerts = {}

    for ts, src, port in sorted(syns):
        attempts, counts = recent[src], port_counts[src]
        attempts.append((ts, port))
        counts[port] += 1

        # Drop attempts that are now older than the window
        while ts - attempts[0][0] > window:
            _, old_port = attempts.popleft()
            counts[old_port] -= 1
            if counts[old_port] == 0:
                del counts[old_port]

        if len(counts) >= threshold:
            alert = alerts.setdefault(src, {"src_ip": src, "first_seen": attempts[0][0], "ports": set()})
            alert["ports"].update(counts)
            alert["last_seen"] = ts

    return list(alerts.values())

def to_iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")

def save_alerts(alerts, db_path, pcap_path):
    """Store each alert in a SQLite database, creating the table the first time."""
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            detected_at  TEXT,
            pcap_file    TEXT,
            src_ip       TEXT,
            unique_ports INTEGER,
            first_seen   TEXT,
            last_seen    TEXT
        )
    """)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for a in alerts:
        # The ? placeholders keep data separate from the SQL command (this blocks SQL injection)
        conn.execute(
            "INSERT INTO alerts (detected_at, pcap_file, src_ip, unique_ports, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (now, pcap_path, a["src_ip"], len(a["ports"]), to_iso(a["first_seen"]), to_iso(a["last_seen"])),
        )
    conn.commit()
    conn.close()


def show_history(db_path):
    """Print every alert saved so far, newest first."""
    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT detected_at, src_ip, unique_ports, pcap_file FROM alerts ORDER BY id DESC"
    ).fetchall()
    conn.close()
    if not rows:
        print("No alerts saved yet.")
    for detected_at, src_ip, unique_ports, pcap_file in rows:
        print(f"{detected_at}  {src_ip:<15}  {unique_ports:>5} ports  ({pcap_file})")


def main():
    parser = argparse.ArgumentParser(description="Detect port scans in a packet capture.")
    parser.add_argument("pcap", nargs="?", help="path to a .pcap or .pcapng file")
    parser.add_argument("--threshold", type=int, default=20, help="different ports that count as a scan (default 20)")
    parser.add_argument("--window", type=float, default=10.0, help="time window in seconds (default 10)")
    parser.add_argument("--db", default="alerts.db", help="SQLite database file (default alerts.db)")
    parser.add_argument("--history", action="store_true", help="show saved alerts and exit")
    args = parser.parse_args()

    if args.history:
        show_history(args.db)
        return
    if not args.pcap:
        parser.error("give a capture file, or use --history")

    syns = get_syns(args.pcap)
    alerts = detect_scans(syns, args.threshold, args.window)
    print(f"Read {len(syns)} connection attempts from {args.pcap}")

    if not alerts:
        print("No port scans detected.")
        return
    for a in alerts:
        print(f"[ALERT] Possible port scan from {a['src_ip']}: {len(a['ports'])} ports "
              f"between {to_iso(a['first_seen'])} and {to_iso(a['last_seen'])}")
    save_alerts(alerts, args.db, args.pcap)
    print(f"Saved {len(alerts)} alert(s) to {args.db}")


if __name__ == "__main__":
    main()