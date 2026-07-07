# Importing necessary libraries
from scapy.all import sniff, Ether, IP, TCP, UDP
import threading
import socket
import time
import datetime
from collections import defaultdict
import matplotlib.pyplot as plt

# Data structures for storing network event information
protocol_events = {"Ethernet": [], "TCP": [], "UDP": []}  # Protocols used in log
data_throughput = defaultdict(int)  # Track total bytes per protocol
latency_records = {}  # Track timestamps for latency calculation
ip_addresses = set()  # Stores unique IP addresses shown in the connections
mac_addresses = set()  # Stores unique MAC addresses shown in the connections
protocol_packet_count = defaultdict(int)  # Track packet count per protocol
connection_timestamps = defaultdict(list)  # Track new connection timestamps per protocol
stop_event = threading.Event()  # Event flag for stopping threads gracefully

# Server configuration constants
HOST_IP = '127.0.0.1'
HOST_PORT = 9999
active_connections = []   # Tracks active client connections to the server

 # Function to handle each client connection
def handle_client(client_socket):
    """Handles individual client connections to allow real-time data sharing."""
    active_connections.append(client_socket)  # Adds client to active connections list

# Starts the TCP server to accept multiple client connections
def start_tcp_server():
    """Starts the TCP server to accept multiple concurrent client connections."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Use TCP
    server_socket.bind((HOST_IP, HOST_PORT))
    server_socket.listen(5)
    print(f"\nServer listening on {HOST_IP}:{HOST_PORT}")
    try:
        while not stop_event.is_set():
            client_socket, addr = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_socket,))
            client_thread.start()
    except KeyboardInterrupt:
        stop_event.set()# Stop the server gracefully on interrupt
    finally:
        # Clean up and close all active connections
        for conn in active_connections:
            conn.close()
            active_connections.remove(conn)
        server_socket.close()

# Logs network events to a file for analysis
def log_network_event(protocol, source_address, destination_address, size):
    timestamp = datetime.datetime.now()
    log_message = f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} - {protocol} - Source: {source_address}, Destination: {destination_address} - Size: {size} bytes\n"
    with open("network_events.log", "a") as log_file:
        log_file.write(log_message)
    update_protocol_data(protocol, source_address, destination_address, size, timestamp)

# Updates internal data structures for tracking network activity
def update_protocol_data(protocol, source_address, destination_address, size, timestamp):
    protocol_events[protocol].append(size)  # Log size for the given protocol
    data_throughput[protocol] += size  # Increment the total data throughput for the protocol
    protocol_packet_count[protocol] += 1  # Increment the packet count for the protocol
    if protocol == "Ethernet":
        mac_addresses.add(source_address)# Track source MAC addresses
    else:
        ip_addresses.add(source_address) # Track source IP addresses

    # Monitor latency and track new connections for each protocol
    connection_key = (source_address, destination_address)# Tuple used to uniquely identify connections
    if protocol in ["TCP", "UDP"]:
            # If this connection hasn't been recorded before, initialize its timestamp data
        if connection_key not in latency_records:
            latency_records[connection_key] = {"start": timestamp}
            connection_timestamps[protocol].append(timestamp) # Log the connection's initial timestamp
        else:
            latency_records[connection_key]["end"] = timestamp# Mark the end of this connection's recorded timestamp
    elif protocol == "Ethernet":
        connection_timestamps[protocol].append(timestamp)  # Log an Ethernet connection's timestamp

# Processes each packet captured by the sniffer, determining its protocol and logging data
def process_packet(packet):
    if stop_event.is_set():# Check if the stop event has been set
        return False  # Exit processing if sniffing should stop
    size = len(packet)# Determine the size of the packet
    if packet.haslayer(Ether):
                # Extract Ethernet source and destination addresses
        eth_src = packet[Ether].src
        eth_dst = packet[Ether].dst
        log_network_event("Ethernet", eth_src, eth_dst, size)
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dest_ip = packet[IP].dst
        if packet.haslayer(TCP):
            log_network_event("TCP", src_ip, dest_ip, size)
        elif packet.haslayer(UDP):
            log_network_event("UDP", src_ip, dest_ip, size)

# Starts packet sniffing, establishes a connection to the server, and begins capturing network traffic
def start_sniffing():
    print("Connecting to server...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((HOST_IP, HOST_PORT))
        print(f"Client: Connected to server at {HOST_IP}:{HOST_PORT}")
        print("Starting packet sniffing...")
        sniff(filter="ip or tcp or udp", prn=process_packet, store=0, stop_filter=lambda x: stop_event.is_set())

# Calculates the throughput (data transfer rate) for each protocol over a specified time interval
def calculate_throughput(interval=10):
    print("\n--- Throughput (bps) ---")
    for protocol, byte_count in data_throughput.items():
        throughput_bps = (byte_count * 8) / interval
        print(f"{protocol}: {throughput_bps:.2f} bps")
        data_throughput[protocol] = 0  # Reset counter

# Calculates the latency, or delay, between the start and end of each connection
def calculate_latency():
    total_latency = 0
    count = 0
    for conn_key, times in latency_records.items():
        if "start" in times and "end" in times:
            latency = (times["end"] - times["start"]).total_seconds() * 1000  # in ms
            total_latency += latency
            count += 1
    avg_latency = total_latency / count if count > 0 else 0
    print(f"\nAverage Latency: {avg_latency:.2f} ms")

# Displays network statistics including connection count, unique IP/MAC addresses, and connection rates
def display_network_statistics():
    print("\n--- Network Statistics ---")
    for protocol, sizes in protocol_events.items():
        num_connections = len(sizes)
        average_size = sum(sizes) / num_connections if num_connections else 0
        print(f"{protocol} Connections: {num_connections}, Average Size: {average_size:.2f} bytes")

# Calculates the rate of new connections for each protocol over a specified time period
    connection_rate_interval = 30  # Time interval (in seconds) used to calculate the connection rate
    current_time = datetime.datetime.now()
    for protocol, timestamps in connection_timestamps.items():
        recent_connections = []
        for t in timestamps:
            if (current_time - t).total_seconds() <= connection_rate_interval:
                recent_connections.append(t)
        connection_rate = len(recent_connections)
        print(f"Rate of New Connections ({protocol}) (last {connection_rate_interval} seconds): {connection_rate} connections")

    print(f"Unique IP Addresses: {len(ip_addresses)}")
    print(f"Unique MAC Addresses: {len(mac_addresses)}")
    print("-------------------------\n")

# Reads log data and generates visualizations for throughput, latency, and protocol usage using matplotlib
def plot_network_graphs():
    # Initializes lists to store timestamps, protocols, and packet sizes for analysis
    timestamps = []
    protocols = []
    sizes = []

# Reads data from the log file with careful parsing to ensure correct format
    try:
        with open("network_events.log", "r") as log_file:
            for line in log_file:
                try:
                    # Splits the log line to extract timestamp, protocol type, and packet size
                    parts = line.split(" - ")

                    # Verifies that the log line has the correct format by checking the number of parts

                    if len(parts) != 4:
                        continue

                    # Extracts the timestamp from the log line
                    timestamp_str = parts[0].strip()
                    protocol = parts[1].strip()
                    size_part = parts[3].strip()

                    # Converts the timestamp string into a datetime object for easier manipulation
                    timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

                    # Extracts the packet size from the string "Size: X bytes" in the log entry
                    size = int(size_part.split(": ")[1].split(" ")[0])

                    # Adds the extracted data (timestamp, protocol, size) to the respective lists
                    timestamps.append(timestamp)
                    protocols.append(protocol)
                    sizes.append(size)

                except (IndexError, ValueError):
                   # Ignores lines that do not match the expected format
                    continue
    except FileNotFoundError:
        print("Log file not found. Unable to plot graphs.")
        return

    # Verifies if any valid data was successfully read from the log file
    if not timestamps or not sizes:
        print("No valid data for plotting.")
        return

# Converts the timestamps to elapsed seconds relative to the first timestamp for throughput visualization
    time_elapsed = [(ts - timestamps[0]).total_seconds() for ts in timestamps]

# Tracks the unique number of IP and MAC addresses, and counts the packets per protocol
    protocol_packet_counts = defaultdict(int)
    unique_ips_per_protocol = defaultdict(set)
    unique_macs_per_protocol = defaultdict(set)

    for protocol, src_addr in zip(protocols, timestamps):
        protocol_packet_counts[protocol] += 1
        if protocol != "Ethernet":
            unique_ips_per_protocol[protocol].add(src_addr)
        else:
            unique_macs_per_protocol[protocol].add(src_addr)

# Organizes data for protocol usage, including the count of unique IP and MAC addresses
    protocol_names = ["Ethernet", "TCP", "UDP"]
    packet_counts = [protocol_packet_counts[proto] for proto in protocol_names]
    unique_ip_counts = [len(unique_ips_per_protocol[proto]) for proto in protocol_names]
    unique_mac_counts = [len(unique_macs_per_protocol[proto]) for proto in protocol_names]

# Sets up a figure with three subplots, arranged in a single row with three columns
    fig, axes = plt.subplots(1, 3, figsize=(18, 6))
    fig.suptitle("Network Monitoring Data Visualization", fontsize=16)

# Plots throughput over time as a line graph
    axes[0].plot(time_elapsed, sizes, label="Throughput (bps)", color="blue")
    axes[0].set_xlabel("Time (seconds)")
    axes[0].set_ylabel("Throughput (bps)")
    axes[0].set_title("Throughput Over Time")
    axes[0].tick_params(axis='x', rotation=45)

# Displays the distribution of latency as a histogram
    axes[1].hist(sizes, bins=20, color='blue', alpha=0.7)
    axes[1].set_xlabel("Latency (ms)")
    axes[1].set_ylabel("Frequency")
    axes[1].set_title("Latency Distribution")

# Displays protocol usage, including unique counts of IP/MAC addresses and packet count, using a bar chart
    bar_width = 0.25
    x = range(len(protocol_names))

# Plots the number of packets captured for each protocol
    axes[2].bar(x, packet_counts, width=bar_width, label="Packets", color="orange")
# Displays the count of unique IP addresses for each protocol using a bar chart
    axes[2].bar([i + bar_width for i in x], unique_ip_counts, width=bar_width, label="Unique IPs", color="blue")
# Displays the count of unique MAC addresses for each protocol using a bar chart
    axes[2].bar([i + 2 * bar_width for i in x], unique_mac_counts, width=bar_width, label="Unique MACs", color="green")

    axes[2].set_xlabel("Protocol")
    axes[2].set_ylabel("Count")
    axes[2].set_title("Protocol Usage with Unique Counts and Packets")
    axes[2].set_xticks([i + bar_width for i in x])
    axes[2].set_xticklabels(protocol_names)
    axes[2].legend()

    plt.tight_layout(rect=[0, 0.03, 1, 0.95])  # Adjusts the layout to ensure that titles and labels fit within the figure

    plt.show()

# Tracks throughput and periodically outputs network statistics at regular intervals
def monitoring_loop():
    try:
        while not stop_event.is_set():
            time.sleep(10)
            calculate_throughput(interval=10)
            if time.time() % 30 < 10:
                display_network_statistics()
    except KeyboardInterrupt:
        print("\nStopping Network Monitoring Tool.")
        stop_event.set()
    finally:
        display_network_statistics()
        plot_network_graphs()
        print("Network monitoring terminated.")


# Initializes the TCP server, starts the sniffing thread, and begins the monitoring process
tcp_server_thread = threading.Thread(target=start_tcp_server)
tcp_server_thread.start()

sniffing_thread = threading.Thread(target=start_sniffing)
sniffing_thread.start()

monitoring_loop()