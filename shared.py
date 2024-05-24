import os
import netifaces


def setup_iptables(port=None, v6=False):
    command = "ip6tables" if v6 else "iptables"
    os.system(f"{command} -A OUTPUT -p tcp --sport {port} --tcp-flags RST RST -j DROP")
    os.system(f"{command} -A INPUT -p tcp --dport {port} -j ACCEPT")


def cleanup_iptables(port=None, v6=False):
    command = "ip6tables" if v6 else "iptables"
    os.system(f"{command} -D OUTPUT -p tcp --sport {port} --tcp-flags RST RST -j DROP")
    os.system(f"{command} -D INPUT -p tcp --dport {port} -j ACCEPT")


def get_default_interface_ip():
    # Get the default gateway
    gws = netifaces.gateways()
    default_interface = gws["default"][netifaces.AF_INET][1]

    # Get the IP address associated with the default interface
    addresses = netifaces.ifaddresses(default_interface)
    ip_address = addresses[netifaces.AF_INET][0]["addr"]

    return ip_address
