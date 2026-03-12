from attack_detection import ip_counter

def get_top_attackers():

    sorted_ips = sorted(
        ip_counter.items(),
        key=lambda x: x[1],
        reverse=True
    )

    return sorted_ips[:5]