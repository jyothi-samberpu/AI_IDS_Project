import csv
from datetime import datetime

def log_attack(ip, attack):

    with open("logs/attack_log.csv","a",newline="") as f:

        writer = csv.writer(f)

        writer.writerow([
            datetime.now(),
            ip,
            attack
        ])