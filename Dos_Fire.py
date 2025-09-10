import time
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
from threading import Thread, Lock
print('\33[1m'+'\33[102m'+"DOS Fire"+'\033[0m'+'\n')
print('\n'+'\033[91m'+"MADE BY : ",'\033[0m','\33[5m'+'\33[32m'+"IMAN"+'\033[0m')
print('\33[4m'+'\33[104m'+"https://github.com/imanhajibagheri"+'\033[0m'+'\n')
pps_threshold = 100
block_duration = 60
block_increment = 60
packet_times = defaultdict(list)
blocked_ips = defaultdict(int)
block_durations = defaultdict(lambda: block_duration)
lock = Lock()
def monitor_traffic(packet):
    if packet.haslayer(IP):
        ip = packet[IP].src
        current_time = time.time()
        with lock:
            packet_times[ip].append(current_time)
            packet_times[ip] = [t for t in packet_times[ip] if current_time - t <= 1]
            if len(packet_times[ip]) > pps_threshold:
                if blocked_ips[ip] == 0:
                    block_ip(ip)
                packet_times[ip] = []
def block_ip(ip):
    print(f"Blocked IP: {ip}")
    blocked_ips[ip] = 1
    duration = block_durations[ip]
    block_durations[ip] += block_increment
    Thread(target=check_and_unblock_ip, args=(ip, duration)).start()
def check_and_unblock_ip(ip, duration):
    time.sleep(duration)
    with lock:
        if len(packet_times[ip]) <= pps_threshold:
            unblock_ip(ip)
        else:
            print(f"Continuing block for IP: {ip}")
            block_durations[ip] += block_increment
            Thread(target=check_and_unblock_ip, args=(ip, block_durations[ip])).start()
def unblock_ip(ip):
    blocked_ips[ip] = 0
    print(f"Unblocked IP: {ip}")
def packet_filter(packet):
    return packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP) or packet.haslayer(ICMP))
if __name__ == "__main__":
    print("Starting packet monitoring...")
    sniff(prn=monitor_traffic, filter="ip", lfilter=packet_filter)
