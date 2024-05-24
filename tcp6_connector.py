import sys
from time import sleep
from scapy.all import IPv6, TCP, RandShort, send, sr1
import netifaces

from shared import setup_iptables, cleanup_iptables


def get_interface_for_ipv6(ipv6_address):
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET6 in addrs:
            for addr in addrs[netifaces.AF_INET6]:
                if addr["addr"].startswith(ipv6_address.split("%")[0].split("::")[0]):
                    return iface
    return None


def get_default_interface_ip6():
    # Get the default gateway for IPv6
    gws = netifaces.gateways()
    print(gws)

    if netifaces.AF_INET6 in gws["default"]:
        default_interface = gws["default"][netifaces.AF_INET6][1]
    else:
        default_interface = gws["default"][netifaces.AF_INET][1]

    # Get the IPv6 address associated with the default interface
    addresses = netifaces.ifaddresses(default_interface)

    if netifaces.AF_INET6 in addresses:
        # Filtering out link-local addresses
        ipv6_addresses = [
            addr
            for addr in addresses[netifaces.AF_INET6]
            if not addr["addr"].startswith("fe80")
        ]
        if ipv6_addresses:
            ip_address = ipv6_addresses[0]["addr"]
        else:
            raise RuntimeError("No global IPv6 address found on default interface")
    else:
        raise RuntimeError("No IPv6 address found on default interface")

    return ip_address


RETRANS_TIME = 5
NUM_RETRIES = 3
CLIENT_IP = get_default_interface_ip6()
OUTPUT_FILE_PATH = "output_v6.txt"


def send_packet_with_retries(packet):
    for attempt in range(NUM_RETRIES):
        response = sr1(packet, timeout=RETRANS_TIME, verbose=False)
        if response:
            return response
        print(f"Retrying... ({attempt + 1}/{NUM_RETRIES})")
    return None


def connect(dst_ip, dst_port):
    if len(sys.argv) != 3:
        print("Usage: python tcp_client.py <dst_ip> <dst_port>")
        sys.exit(1)

    if "%" not in dst_ip:
        dst_interface = get_interface_for_ipv6(dst_ip)
        if not dst_interface:
            print("Invalid IPv6 Address")
            sys.exit(1)
        dst_ip += "%" + dst_interface

    src_port = RandShort()._fix()

    setup_iptables(src_port, True)

    response_data = b""

    try:
        # Create TCP SYN packet
        ip = IPv6(src=CLIENT_IP, dst=dst_ip)
        syn = TCP(sport=src_port, dport=dst_port, flags="S", seq=1000)
        syn_ack = sr1(ip / syn, timeout=2)
        if syn_ack:
            curr_seq = syn_ack.ack
            curr_ack = syn_ack.seq + 1

            while True:
                response = send_packet_with_retries(
                    ip
                    / TCP(
                        sport=src_port,
                        dport=dst_port,
                        flags="A",
                        seq=curr_seq,
                        ack=curr_ack,
                    ),
                )
                if not response:
                    # send FIN if we arent getting any more responses
                    fin_response = sr1(
                        ip
                        / TCP(
                            sport=src_port,
                            dport=dst_port,
                            flags="FA",
                            seq=curr_seq,
                            ack=curr_ack,
                        )
                    )
                    if fin_response[TCP].seq == curr_ack:
                        send(
                            ip
                            / TCP(
                                sport=src_port,
                                dport=dst_port,
                                flags="A",
                                seq=fin_response[TCP].ack,
                                ack=fin_response[TCP].seq + 1,
                            )
                        )
                    break
                print(
                    f"Received packet from {dst_ip}:{dst_port} with flags {response[TCP].flags}"
                )
                if "R" in response[TCP].flags:
                    return
                curr_seq = response.ack
                curr_ack = response.seq + len(response[TCP].payload)
                response_data += bytes(response[TCP].payload)
                if "F" in response[TCP].flags and "A" in response[TCP].flags:
                    # fin sequence
                    send(
                        ip
                        / TCP(
                            sport=src_port,
                            dport=dst_port,
                            flags="A",
                            seq=curr_seq,
                            ack=curr_ack,
                        )
                    )
                    send(
                        ip
                        / TCP(
                            sport=src_port,
                            dport=dst_port,
                            flags="FA",
                            seq=curr_seq,
                            ack=curr_ack + 1,
                        )
                    )
                    break
                sleep(0.01)
            with open(OUTPUT_FILE_PATH, "wb") as f:
                f.write(response_data)
        else:
            print("No SYN-ACK received.")

    finally:
        cleanup_iptables(src_port, True)


if __name__ == "__main__":
    dst_ip = sys.argv[1]
    dst_port = int(sys.argv[2])

    connect(dst_ip, dst_port)
