"""Generates a SYNTHETIC log in the same format as the live monitor.

Useful for trying the graphs without admin rights or a network capture.
    python examples/generate_sample_log.py > examples/sample_network_events.log
"""

import datetime
import random

random.seed(7)
start = datetime.datetime(2026, 1, 1, 10, 0, 0)
macs = [f"aa:bb:cc:00:00:{i:02x}" for i in range(1, 6)]
ips = [f"192.168.1.{i}" for i in range(10, 22)]

for second in range(60):
    burst = 1.0 + 2.5 * (30 <= second < 40)          # a traffic burst in the middle
    for _ in range(int(random.randint(4, 9) * burst)):
        stamp = (start + datetime.timedelta(seconds=second)).strftime("%Y-%m-%d %H:%M:%S")
        proto = random.choices(["TCP", "UDP"], weights=[0.7, 0.3])[0]
        size = random.choice([60, 74, 98, 150, 576, 1200, 1514]) + random.randint(-20, 20)
        src, dst = random.sample(ips, 2)
        print(f"{stamp} - Ethernet - Source: {random.choice(macs)}, Destination: {random.choice(macs)} - Size: {size} bytes")
        print(f"{stamp} - {proto} - Source: {src}, Destination: {dst} - Size: {size} bytes")
