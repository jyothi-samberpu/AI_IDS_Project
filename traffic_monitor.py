import time

packet_count = 0
start_time = time.time()

def update_traffic(packet):

    global packet_count
    packet_count += 1