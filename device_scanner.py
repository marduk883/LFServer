import socket
import os
import subprocess
import re
from threading import Thread
import queue
import time
import json
from datetime import datetime
from tables import m883lfs, MacAdrs, app 


class NetworkScanner:
    def __init__(self):
        self.hostname = socket.gethostname()
        self.local_ip = socket.gethostbyname(self.hostname)
        self.network = '.'.join(self.local_ip.split('.')[:-1])
        self.devices = queue.Queue()
        self.vendors = self.load_vendor_database()
        self.common_ports = {
            'HTTP': 80,
            'HTTPS': 443,
            'SSH': 22,
            'FTP': 21,
            'SMB': 445,
            'RDP': 3389,
            'MySQL': 3306,
            'DNS': 53,
            'SMTP': 25,
            'POP3': 110,
            'NetBIOS': 139,
            'iOS Sync': 62078
        }
        self.device_signatures = {
            'Smartphone': {
                'ports': [62078],
                'mac_prefixes': ['34:C9:3D', '68:D9:3C', '14:7D:DA', 'F4:5C:89', '28:6C:07']
            },
            'Computer': {
                'ports': [445, 139, 135, 3389],
                'mac_prefixes': ['00:05:02', '00:0C:29', '00:50:56', '00:1A:A0']
            },
            'IoT Device': {
                'ports': [80, 8080, 8081, 2323],
                'mac_prefixes': ['18:FE:34', 'E4:71:85', 'EC:FA:BC']
            },
            'Network Device': {
                'ports': [23, 53, 67, 68],
                'mac_prefixes': ['00:50:F1', 'E4:8D:8C', '00:11:22']
            }
        }

    def load_vendor_database(self):
        try:
            with open('vendor_mac.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {
                '0050F1': 'TRENDnet',
                'EE433F': 'Huawei',
                'FCAA14': 'Samsung',
                '74D435': 'Samsung',
                '001A11': 'Google',
                '002248': 'Microsoft',
                '34C93D': 'Apple iPhone',
                '68D93C': 'Apple iPad',
                '147DDA': 'Apple Device',
                'F45C89': 'Samsung Mobile',
                '286C07': 'Xiaomi'
            }

    def get_mac_address(self, ip):
        try:
            # Try arp -a first
            result = subprocess.check_output(f'arp -a {ip}', shell=True).decode()
            mac = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', result)
            if mac:
                return mac.group(0)

            # If arp fails, try getmac
            result = subprocess.check_output(f'getmac /NH /S {ip}', shell=True).decode()
            mac = re.search(r'([0-9A-Fa-f]{2}-){5}([0-9A-Fa-f]{2})', result)
            return mac.group(0) if mac else "Unknown"
        except:
            return "Unknown"

    def get_device_name(self, ip):
        try:
            # Try multiple name resolution methods
            try:
                return socket.gethostbyaddr(ip)[0]
            except:
                try:
                    result = subprocess.check_output(f'ping -a {ip} -n 1', shell=True).decode()
                    name = re.search(r'Pinging ([^\s]+)', result)
                    return name.group(1) if name else "Unknown"
                except:
                    return "Unknown"
        except:
            return "Unknown"

    def get_device_category(self, mac, open_ports):
        try:
            if mac != "Unknown":
                mac_prefix = mac[:8].upper()
                # Check MAC prefix signatures
                for category, signature in self.device_signatures.items():
                    if any(prefix in mac_prefix for prefix in signature['mac_prefixes']):
                        return category

            # Check port signatures
            for category, signature in self.device_signatures.items():
                if any(port in open_ports for port in signature['ports']):
                    return category

            return "Unknown Device"
        except:
            return "Unknown Device"

    def get_device_type(self, mac):
        if mac == "Unknown":
            return "Unknown"
        try:
            vendor_id = mac.replace(':', '').replace('-', '')[:6].upper()
            return self.vendors.get(vendor_id, "Unknown Vendor")
        except:
            return "Unknown"

    def get_os_info(self, ip, open_ports):
        try:
            # Method 1: TTL Analysis
            ping = subprocess.check_output(f'ping -n 1 -w 1000 {ip}', shell=True).decode()
            ttl = re.search(r'TTL=(\d+)', ping)
            
            if ttl:
                ttl_value = int(ttl.group(1))
                if ttl_value <= 64:
                    return "Linux/Unix"
                elif ttl_value <= 128:
                    if 445 in open_ports or 3389 in open_ports:
                        return "Windows"
                    return "Windows/IoT"
                elif ttl_value <= 254:
                    return "Solaris/AIX"
            
            # Method 2: Port Analysis
            if 445 in open_ports and 139 in open_ports:
                return "Windows"
            elif 22 in open_ports and 62078 in open_ports:
                return "iOS"
            elif 22 in open_ports:
                return "Linux/Unix"
            
            return "Unknown OS"
        except:
            return "Unknown OS"

    def check_ports(self, ip):
        open_ports = []
        for port in self.common_ports.values():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                sock.close()
            except:
                continue
        return open_ports

    def scan_host(self, ip):
        try:
            # Try multiple detection methods
            is_up = False
            
            # Method 1: Ping
            try:
                ping = subprocess.check_output(
                    f'ping -n 2 -w 1000 {ip}',
                    shell=True,
                    stderr=subprocess.DEVNULL
                ).decode()
                is_up = "TTL=" in ping or "bytes=" in ping
            except:
                pass

            # Method 2: Port Scan
            open_ports = self.check_ports(ip)
            if not is_up:
                is_up = len(open_ports) > 0

            if is_up:
                mac = self.get_mac_address(ip)
                name = self.get_device_name(ip)
                device_type = self.get_device_type(mac)
                device_category = self.get_device_category(mac, open_ports)
                os_info = self.get_os_info(ip, open_ports)

                # MAC adresini veritabanına kaydet
                if mac != "Unknown":
                    with app.app_context():  # Uygulama bağlamını oluştur
                        existing_mac = MacAdrs.query.filter_by(mac_adrs=mac).first()
                        if not existing_mac:
                            new_mac = MacAdrs(mac_adrs=mac, is_locked=False)
                            m883lfs.session.add(new_mac)
                            m883lfs.session.commit()

                device_info = {
                    'ip': ip,
                    'mac': mac,
                    'name': name,
                    'vendor': device_type,
                    'category': device_category,
                    'os': os_info,
                    'ports': open_ports,
                    'status': 'Active'
                }
                
                self.devices.put(device_info)
                #print(f"Found: {ip} ({name}) - {device_category} - {device_type} - {os_info}")
                #if open_ports:
                #    ports_info = [f"{port}({list(self.common_ports.keys())[list(self.common_ports.values()).index(port)]})" 
                #                for port in open_ports]
                #    print(f"Open ports: {', '.join(ports_info)}")

        except Exception as e:
            print(f"Error scanning {ip}: {str(e)}")

    def scan(self):
        print(f"Scanning network: {self.network}.0/24")
        print("-" * 70)
        
        threads = []
        for i in range(1, 255):
            ip = f"{self.network}.{i}"
            t = Thread(target=self.scan_host, args=(ip,))
            t.daemon = True
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        devices = []
        while not self.devices.empty():
            devices.append(self.devices.get())

        return sorted(devices, key=lambda x: tuple(map(int, x['ip'].split('.'))))

    #def save_results(self, devices, scan_type):
    #    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    #    filename = f'scan_results_{scan_type}_{timestamp}.json'
    #    
    #    with open(filename, 'w', encoding='utf-8') as f:
    #        json.dump(devices, f, indent=4)
    #    
    #    print(f"\nResults saved to {filename}")
    #    return filename

#if __name__ == "__main__":
#    scanner = NetworkScanner()
#    print("Network Scanner v2.0")
#    print("1. Quick Scan (Basic)")
#    print("2. Deep Scan (Full)")
#    choice = input("Select scan type (1/2): ")
#
#    devices = scanner.scan()
#    
#    if choice == "1":
#        print("\nBasic Results:")
#        print("-" * 70)
#        for device in devices:
#            print(f"{device['ip']}\t{device['name'][:15]}\t{device['category']}")
#        scanner.save_results(devices, "quick")
#    
#    elif choice == "2":
#        print("\nDetailed Results:")
#        print("-" * 70)
#        for device in devices:
#            print(f"IP: {device['ip']}")
#            print(f"Name: {device['name']}")
#            print(f"MAC: {device['mac']}")
#            print(f"Category: {device['category']}")
#            print(f"Vendor: {device['vendor']}")
#            print(f"OS: {device['os']}")
#            if device['ports']:
#                ports_info = [f"{port}({list(scanner.common_ports.keys())[list(scanner.common_ports.values()).index(port)]})" 
#                            for port in device['ports']]
#                print(f"Open ports: {', '.join(ports_info)}")
#            print("-" * 30)
#        scanner.save_results(devices, "deep")
#    
#    else:
#        print("Invalid choice!")
#
#    print(f"\nTotal devices found: {len(devices)}")