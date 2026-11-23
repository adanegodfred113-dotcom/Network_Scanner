"""
NETWORK SCANNER - Beginner Python project
Purpose:
  * Discover responsive devices on a small, authorized private LAN.
  * Check a short list of TCP ports on discovered devices.
  * Save results to a text report.

Uses only Python's standard library. No internet connection or pip installs needed.
Run: python network_scanner.py
"""

import ipaddress
import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# These are common TCP service ports. This is a small, basic list, not a full scan.
COMMON_PORTS = [22, 53, 80, 443, 445, 554, 8080]
PING_TIMEOUT_MS = 700
CONNECT_TIMEOUT_SECONDS = 0.35
MAX_HOSTS = 256
MAX_WORKERS = 64


def get_local_ip():
    """Find the IPv4 address used by this computer on its local network."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # This does not send application data or require an internet connection.
        # It asks the operating system which local interface it would use.
        sock.connect(("192.0.2.1", 80))  # TEST-NET address; not a real destination
        return sock.getsockname()[0]
    except OSError:
        return socket.gethostbyname(socket.gethostname())
    finally:
        sock.close()


def get_default_network():
    """Suggest a /24 network based on the computer's local IPv4 address."""
    local_ip = get_local_ip()
    network = ipaddress.ip_network(local_ip + "/24", strict=False)
    return network


def ping_host(ip):
    """Return True if the operating system's ping command gets a reply."""
    system = platform.system().lower()

    if system == "windows":
        command = ["ping", "-n", "1", "-w", str(PING_TIMEOUT_MS), str(ip)]
    else:
        # -c 1 sends one ping; -W 1 uses a short timeout on Linux/macOS.
        command = ["ping", "-c", "1", "-W", "1", str(ip)]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=False
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def check_port(ip, port):
    """Return True when a TCP connection to this IP and port succeeds."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(CONNECT_TIMEOUT_SECONDS)
            return sock.connect_ex((str(ip), port)) == 0
    except OSError:
        return False


def scan_device(ip):
    """Check one address. A ping reply OR an open selected port marks it responsive."""
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


def scan_network(network):
    """Scan every usable address in the supplied private network."""
    hosts = list(network.hosts())
    results = []

    print(f"\nScanning {network} ({len(hosts)} possible device addresses)...")
    print("This may take a little time. Please wait.\n")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        tasks = {executor.submit(scan_device, ip): ip for ip in hosts}

        completed = 0
        for future in as_completed(tasks):
            completed += 1
            try:
                result = future.result()
                if result["responsive"]:
                    results.append(result)
                    ports_text = ", ".join(map(str, result["open_ports"])) or "none detected"
                    print(f"[FOUND] {result['ip']:<15} Open TCP ports: {ports_text}")
            except Exception as error:
                print(f"[WARNING] Could not scan {tasks[future]}: {error}")

            if completed % 25 == 0 or completed == len(hosts):
                print(f"Progress: {completed}/{len(hosts)} addresses checked")

    results.sort(key=lambda item: ipaddress.ip_address(item["ip"]))
    return results


def save_report(network, results):
    """Write the scan summary to a timestamped text file."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"network_scan_{timestamp}.txt"

    with open(filename, "w", encoding="utf-8") as report:
        report.write("NETWORK SCANNER REPORT\n")
        report.write("=" * 50 + "\n")
        report.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.write(f"Network: {network}\n")
        report.write(f"Responsive devices: {len(results)}\n\n")

        for number, device in enumerate(results, start=1):
            ports = ", ".join(map(str, device["open_ports"])) or "No selected ports detected"
            report.write(f"{number}. IP address: {device['ip']}\n")
            report.write(f"   Ping reply: {'Yes' if device['ping'] else 'No'}\n")
            report.write(f"   Open TCP ports: {ports}\n\n")

        report.write(
            "Note: No response does not prove a device is offline. "
            "Firewalls may block ping and connection attempts.\n"
        )

    return filename


def main():
    print("=" * 55)
    print("              PYTHON NETWORK SCANNER")
    print("=" * 55)
    print("Use only on a network you own or are authorized to test.\n")

    try:
        local_ip = get_local_ip()
        suggested_network = get_default_network()
        print(f"Your computer's local IPv4 address: {local_ip}")
        print(f"Suggested network range: {suggested_network}")

        entered_network = input(
            "\nEnter the network in CIDR format, or press Enter to use the suggestion: "
        ).strip()

        if entered_network:
            network = ipaddress.ip_network(entered_network, strict=False)
        else:
            network = suggested_network

        if not network.is_private:
            print("For safety, this beginner project accepts private network ranges only.")
            return

        if network.version != 4:
            print("This version supports IPv4 networks only.")
            return

        if network.num_addresses > MAX_HOSTS:
            print(f"Network is too large. Use a network with no more than {MAX_HOSTS} addresses.")
            return

        confirmation = input(
            f"\nConfirm that you are authorized to scan {network} (yes/no): "
        ).strip().lower()

        if confirmation != "yes":
            print("Scan cancelled.")
            return

        results = scan_network(network)

        print("\n" + "=" * 55)
        print(f"SCAN COMPLETE - {len(results)} responsive device(s) found.")
        print("=" * 55)

        if not results:
            print("No responsive devices were detected.")
            print("Check that you entered the correct network and are connected to Wi-Fi/LAN.")

        report_file = save_report(network, results)
        print(f"\nReport saved as: {report_file}")
        print("Remember: only the listed TCP ports were checked.")

    except ValueError as error:
        print(f"Invalid network address: {error}")
    except KeyboardInterrupt:
        print("\nScan stopped by user.")
    except OSError as error:
        print(f"Operating system error: {error}")


if __name__ == "__main__":
    main()
