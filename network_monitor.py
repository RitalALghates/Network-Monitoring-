#!/usr/bin/env python3
"""Network Monitoring Tool.

Captures live traffic with Scapy, logs every Ethernet / TCP / UDP packet to a file,
prints periodic statistics (throughput, connection counts, unique addresses) and
draws summary graphs when it stops.

Usage
-----
    sudo python network_monitor.py                 # live capture (needs admin / root)
    python network_monitor.py --plot-only network_events.log
    python network_monitor.py --plot-only examples/sample_network_events.log --save docs/sample_graphs.png
"""

import argparse
import datetime
import socket
import threading
import time
from collections import Counter, defaultdict

PROTOCOLS = ("Ethernet", "TCP", "UDP")
DEFAULT_LOG_FILE = "network_events.log"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9999
LOG_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


# --------------------------------------------------------------------------- #
# Live monitor
# --------------------------------------------------------------------------- #
class NetworkMonitor:
    """Sniffs packets, keeps running statistics and writes them to a log file."""

    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT, log_file=DEFAULT_LOG_FILE):
        self.host = host
        self.port = port
        self.log_file = log_file

        self.stop_event = threading.Event()
        self._lock = threading.Lock()

        self.protocol_events = {p: [] for p in PROTOCOLS}      # packet sizes per protocol
        self.data_throughput = defaultdict(int)                # bytes since the last report
        self.protocol_packet_count = defaultdict(int)
        self.connection_timestamps = defaultdict(list)         # first packet of every new connection
        self.flow_times = {}                                   # (src, dst) -> {"start": ..., "end": ...}
        self.ip_addresses = set()
        self.mac_addresses = set()
        self.active_connections = []

    # -- TCP server used to share the capture with clients ------------------- #
    def _handle_client(self, client_socket):
        with self._lock:
            self.active_connections.append(client_socket)

    def start_tcp_server(self):
        """Accepts client connections until the monitor is stopped."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(5)
        server.settimeout(1.0)  # lets the loop notice stop_event
        print(f"\nServer listening on {self.host}:{self.port}")
        try:
            while not self.stop_event.is_set():
                try:
                    client_socket, _ = server.accept()
                except socket.timeout:
                    continue
                threading.Thread(target=self._handle_client, args=(client_socket,), daemon=True).start()
        finally:
            with self._lock:
                for conn in self.active_connections:
                    conn.close()
                self.active_connections.clear()
            server.close()

    # -- Packet handling ---------------------------------------------------- #
    def log_event(self, protocol, source, destination, size):
        """Writes one event to the log file and updates the in-memory statistics."""
        timestamp = datetime.datetime.now()
        line = (
            f"{timestamp.strftime(LOG_TIME_FORMAT)} - {protocol} - "
            f"Source: {source}, Destination: {destination} - Size: {size} bytes\n"
        )
        with self._lock:
            with open(self.log_file, "a", encoding="utf-8") as log:
                log.write(line)
            self._update(protocol, source, destination, size, timestamp)

    def _update(self, protocol, source, destination, size, timestamp):
        self.protocol_events[protocol].append(size)
        self.data_throughput[protocol] += size
        self.protocol_packet_count[protocol] += 1

        if protocol == "Ethernet":
            self.mac_addresses.add(source)
            self.connection_timestamps[protocol].append(timestamp)
            return

        self.ip_addresses.add(source)
        key = (source, destination)
        if key not in self.flow_times:
            self.flow_times[key] = {"start": timestamp}
            self.connection_timestamps[protocol].append(timestamp)
        else:
            self.flow_times[key]["end"] = timestamp

    def process_packet(self, packet):
        """Scapy callback: classify the packet and log it."""
        from scapy.all import IP, TCP, UDP, Ether  # imported lazily so --plot-only needs no Scapy

        size = len(packet)
        if packet.haslayer(Ether):
            self.log_event("Ethernet", packet[Ether].src, packet[Ether].dst, size)
        if packet.haslayer(IP):
            src, dst = packet[IP].src, packet[IP].dst
            if packet.haslayer(TCP):
                self.log_event("TCP", src, dst, size)
            elif packet.haslayer(UDP):
                self.log_event("UDP", src, dst, size)

    def start_sniffing(self):
        from scapy.all import sniff

        print("Starting packet sniffing... (Ctrl+C to stop)")
        sniff(
            filter="ip or tcp or udp",
            prn=self.process_packet,
            store=0,
            stop_filter=lambda _: self.stop_event.is_set(),
        )

    # -- Reports ------------------------------------------------------------- #
    def print_throughput(self, interval):
        print("\n--- Throughput (bps) ---")
        with self._lock:
            for protocol, byte_count in list(self.data_throughput.items()):
                print(f"{protocol}: {(byte_count * 8) / interval:.2f} bps")
                self.data_throughput[protocol] = 0

    def print_flow_duration(self):
        durations = [
            (t["end"] - t["start"]).total_seconds() * 1000
            for t in self.flow_times.values()
            if "end" in t
        ]
        average = sum(durations) / len(durations) if durations else 0.0
        print(f"\nAverage flow duration: {average:.2f} ms")

    def print_statistics(self, rate_window=30):
        print("\n--- Network Statistics ---")
        with self._lock:
            for protocol, sizes in self.protocol_events.items():
                average = sum(sizes) / len(sizes) if sizes else 0.0
                print(f"{protocol} packets: {len(sizes)}, average size: {average:.2f} bytes")

            now = datetime.datetime.now()
            for protocol, stamps in self.connection_timestamps.items():
                recent = sum(1 for t in stamps if (now - t).total_seconds() <= rate_window)
                print(f"New {protocol} connections (last {rate_window}s): {recent}")

            print(f"Unique IP addresses: {len(self.ip_addresses)}")
            print(f"Unique MAC addresses: {len(self.mac_addresses)}")
        print("-------------------------\n")

    def monitoring_loop(self, interval=10, stats_every=3):
        """Prints throughput every `interval` seconds and full statistics every `stats_every` rounds."""
        rounds = 0
        try:
            while not self.stop_event.is_set():
                time.sleep(interval)
                rounds += 1
                self.print_throughput(interval)
                if rounds % stats_every == 0:
                    self.print_statistics()
        except KeyboardInterrupt:
            print("\nStopping Network Monitoring Tool.")
        finally:
            self.stop_event.set()
            self.print_flow_duration()
            self.print_statistics()

    def run(self, interval=10):
        threads = [
            threading.Thread(target=self.start_tcp_server, daemon=True),
            threading.Thread(target=self.start_sniffing, daemon=True),
        ]
        for t in threads:
            t.start()
        self.monitoring_loop(interval)
        for t in threads:
            t.join(timeout=3)
        print("Network monitoring terminated.")


# --------------------------------------------------------------------------- #
# Log parsing and plotting
# --------------------------------------------------------------------------- #
def parse_log(path):
    """Reads a log file and returns a list of events (dicts). Malformed lines are skipped."""
    events = []
    try:
        with open(path, "r", encoding="utf-8") as log:
            for line in log:
                parts = line.rstrip("\n").split(" - ")
                if len(parts) != 4:
                    continue
                try:
                    timestamp = datetime.datetime.strptime(parts[0].strip(), LOG_TIME_FORMAT)
                    protocol = parts[1].strip()
                    addresses = parts[2].strip()  # "Source: a, Destination: b"
                    source = addresses.split("Source:")[1].split(",")[0].strip()
                    size = int(parts[3].strip().split(": ")[1].split(" ")[0])
                except (IndexError, ValueError):
                    continue
                events.append({"time": timestamp, "protocol": protocol, "source": source, "size": size})
    except FileNotFoundError:
        print(f"Log file not found: {path}")
    return events


def plot_network_graphs(log_file=DEFAULT_LOG_FILE, save_path=None):
    """Draws throughput over time, packet-size distribution and protocol usage from a log file."""
    import matplotlib

    if save_path:
        matplotlib.use("Agg")  # no display needed when saving to a file
    import matplotlib.pyplot as plt

    events = parse_log(log_file)
    if not events:
        print("No valid data for plotting.")
        return

    start = events[0]["time"]
    bytes_per_second = Counter()
    for e in events:
        bytes_per_second[int((e["time"] - start).total_seconds())] += e["size"]
    seconds = range(0, max(bytes_per_second) + 1)
    kbps = [bytes_per_second.get(s, 0) * 8 / 1000 for s in seconds]

    packet_counts = Counter(e["protocol"] for e in events)
    unique_sources = {p: len({e["source"] for e in events if e["protocol"] == p}) for p in PROTOCOLS}

    fig, axes = plt.subplots(1, 3, figsize=(18, 5.5))
    fig.suptitle("Network Monitoring Data Visualization", fontsize=16, fontweight="bold")

    axes[0].plot(list(seconds), kbps, color="#3d5afe", linewidth=1.8)
    axes[0].fill_between(list(seconds), kbps, color="#3d5afe", alpha=0.15)
    axes[0].set(title="Throughput Over Time", xlabel="Time (seconds)", ylabel="Throughput (kbit/s)")

    axes[1].hist([e["size"] for e in events], bins=20, color="#7c4dff", alpha=0.85, edgecolor="white")
    axes[1].set(title="Packet Size Distribution", xlabel="Packet size (bytes)", ylabel="Frequency")

    width = 0.38
    positions = range(len(PROTOCOLS))
    axes[2].bar([i - width / 2 for i in positions], [packet_counts[p] for p in PROTOCOLS],
                width=width, label="Packets", color="#ff9100")
    axes[2].bar([i + width / 2 for i in positions], [unique_sources[p] for p in PROTOCOLS],
                width=width, label="Unique sources (IP / MAC)", color="#00b8d4")
    axes[2].set_xticks(list(positions))
    axes[2].set_xticklabels(PROTOCOLS)
    axes[2].set(title="Protocol Usage", xlabel="Protocol", ylabel="Count")
    axes[2].legend()

    for ax in axes:
        ax.grid(alpha=0.25)
    plt.tight_layout(rect=[0, 0.02, 1, 0.94])

    if save_path:
        fig.savefig(save_path, dpi=110)
        print(f"Saved graphs to {save_path}")
    else:
        plt.show()


# --------------------------------------------------------------------------- #
# Command line
# --------------------------------------------------------------------------- #
def main():
    parser = argparse.ArgumentParser(description="Capture and visualise network traffic.")
    parser.add_argument("--log", default=DEFAULT_LOG_FILE, help="log file to write (default: %(default)s)")
    parser.add_argument("--host", default=DEFAULT_HOST, help="TCP server host (default: %(default)s)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="TCP server port (default: %(default)s)")
    parser.add_argument("--interval", type=int, default=10, help="seconds between throughput reports")
    parser.add_argument("--plot-only", metavar="LOG", help="do not capture; draw graphs from an existing log file")
    parser.add_argument("--save", metavar="PNG", help="save the graphs to an image instead of opening a window")
    args = parser.parse_args()

    if args.plot_only:
        plot_network_graphs(args.plot_only, args.save)
        return

    monitor = NetworkMonitor(args.host, args.port, args.log)
    try:
        monitor.run(args.interval)
    finally:
        plot_network_graphs(args.log, args.save)


if __name__ == "__main__":
    main()
