import os
import getpass
from datetime import datetime
from flask import request
import log_config
import requests
import subprocess
import re

logger = log_config.setup_logging()

class UserInfo:
    def get_system_username(self):
        """Retrieve the username from environment variables or fallback to getpass."""
        try:
            username = os.environ.get("USERNAME") or os.environ.get("USER") or getpass.getuser()
        except Exception as e:
            username = "Unknown User"
        return username

    def get_ip(self):
        """Retrieve the global IP address using an external service."""
        ip_address = "Unknown IP Address"
        try:
            response = requests.get('https://api.ipify.org?format=json')
            ip_address = response.json().get('ip', 'Unknown IP Address')
        except Exception as e:
            logger.error(f"Error retrieving IP address: {e}")
        logger.info(f"IP Address: {ip_address}")
        return ip_address

    def get_login_date(self):
        """Retrieve the current login date and time."""
        login_time = "Unknown Time"
        try:
            login_time = datetime.now()
        except Exception as e:
            logger.error(f"Error retrieving login date: {e}")
        logger.info(f"Login Time: {login_time}")
        return login_time

    def get_platform_info(self):
        """Determine the user's device type from the User-Agent header."""
        device_type = "Unknown Platform"
        try:
            user_agent = request.headers.get('User-Agent', '').lower()
            if "windows" in user_agent:
                device_type = "Windows"
            elif "android" in user_agent:
                device_type = "Android"
            elif "macintosh" in user_agent:
                device_type = "macOS"
            elif "iphone" in user_agent:
                device_type = "iOS"
            elif "linux" in user_agent:
                device_type = "Linux"
        except Exception as e:
            logger.error(f"Error determining platform info: {e}\n")
        logger.info(f"Device Type: {device_type}\n")
        return device_type
      
    def log_critical_if_all_unknown(self):
        """Log a critical message if all three pieces of information are unknown."""
        ip_address = self.get_ip()
        login_time = self.get_login_date()
        device_type = self.get_platform_info()

        if ip_address == "Unknown IP Address" and login_time == "Unknown Time" and device_type == "Unknown Platform":
            logger.critical("Failed to retrieve IP address, login time, and device type.\n")

    def get_mac(self, ip_address):
        """Retrieve the MAC address for a given IP address."""
        try:
            if os.name == 'nt':  # Windows
                arp_result = subprocess.check_output(['arp', '-a', ip_address], timeout=2).decode('utf-8')
                mac_address_search = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', arp_result)
                if mac_address_search:
                    mac_address = mac_address_search.group(0)
                    logger.info(f"MAC Address for IP {ip_address}: {mac_address}")
                    return mac_address
            else:  # Linux/macOS
                ip_route_result = subprocess.check_output(['ip', 'route', 'get', ip_address], timeout=2).decode('utf-8')
                dev_search = re.search(r'dev\s+(\w+)', ip_route_result)
                if dev_search:
                    interface = dev_search.group(1)
                    ifconfig_result = subprocess.check_output(['ifconfig', interface], timeout=2).decode('utf-8')
                    mac_address_search = re.search(r'ether\s+([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', ifconfig_result)
                    if mac_address_search:
                        mac_address = mac_address_search.group(1)
                        logger.info(f"MAC Address for IP {ip_address}: {mac_address}")
                        return mac_address
        except subprocess.TimeoutExpired:
            logger.error("MAC address retrieval timed out.")
        except Exception as e:
            logger.error(f"Error retrieving MAC address: {e}")
        return "Unknown MAC Address"