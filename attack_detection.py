from log_system import log_attack
from collections import defaultdict

ip_counter = defaultdict(int)

def detect_attack(packet):

    if packet.haslayer("IP"):

        src_ip = packet["IP"].src

        ip_counter[src_ip] += 1

        if ip_counter[src_ip] > 100:

            print("⚠ Possible attack from", src_ip)

            log_attack(src_ip, "Traffic Flood")