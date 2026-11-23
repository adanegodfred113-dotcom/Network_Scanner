import ipaddress
import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from platform import system

import main

COMMON_PORTS = [22, 53, 80, 443, 445, 554, 8080]
PING_TIMEOUT_MS = 700
CONNECT_TIMEOUT_SECONDS = 0.35
MAX_HOST = 256
MAX_WORKERS = 64

#----------------- FINDING MY COMPUTER'S LOCAL IP------
def get_local_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 80))
        return sock.getsockname()[0]
    except OSError:
        return socket.gethostbyname(socket.gethostname())
    finally:
        sock.close()

#----- SUGGESTING A LOCAL NETWORK RANGE ---
def get_default_network():
    local_ip = get_local_ip()
    network = ipaddress.ip_network(local_ip + "/24", strict=False)
    return network

#----- CHECKING WHETHER A DEVICE RESPONDS TO PING ---
def ping_host(ip):
    system = platform.system().lower()
    if system == "windows":
        command = ["ping", "-n", "-l", "w", "700", str(ip)]
    else:
        command = ["ping", "-c", "1", "-w", "l", str(ip)]
    try:
        result = subprocess.run(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2, check=False
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False

#---TESTING A TCP PORT-----
def check_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.35)
            return sock.connect_ex((str(ip), port)) == 0
    except OSError:
        return False

#COMBINING PING AND PORT CHECKS FOR ONE DEVICE
def scan_device(ip):
    ping_reply = ping_host(ip)
    open_ports = []
    for port in COMMON_PORTS:
        if check_port(ip, port):
            open_ports.append(port)
    responsive = ping_reply or bool(open_ports)
    return {
        "ip": str(ip),
        "responsive": responsive,
        "ping": ping_reply,
        "open_ports": open_ports
    }

#---SCANNING THE NETWORK---
def scan_network(network):
    hosts = list(network.hosts())
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        tasks = {executor.submit(scan_device, ip): ip for ip in hosts}
        for future in as_completed(tasks):
            result = future.result()
            if result["responsive"]:
                results.append(result)
    results.sort(key=lambda item: ipaddress.ip_address(item["ip"]))
    return results


#---SAVING REPORT---
def save_report(network, results):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"network_scan_{timestamp}.txt"
    with open(filename, "w", encoding="utf-8") as report:
        report.write("NETWORK SCANNER REPORT\\n")
        report.write(f"Network: {network}\\n")
        report.write(f"Responsive devices: {len(results)}\\n")
        for device in results:
            report.write(f"{device['ip']} - {device['open_ports']}\\n")
            return filename
if __name__ == "__main__":
    main()