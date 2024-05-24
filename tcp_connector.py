import sys
from time import sleep
from scapy.all import IP, TCP, RandShort, send, sr1

from shared import setup_iptables, cleanup_iptables, get_default_interface_ip

RETRANS_TIME = 5
NUM_RETRIES = 3
CLIENT_IP = get_default_interface_ip()
OUTPUT_FILE_PATH = "output.txt"


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

    src_port = RandShort()._fix()

    setup_iptables(src_port)

    response_data = b""

    try:
        # Create TCP SYN packet
        ip = IP(src=CLIENT_IP, dst=dst_ip)
        print(src_port)
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
        cleanup_iptables(src_port)


if __name__ == "__main__":
    dst_ip = sys.argv[1]
    dst_port = int(sys.argv[2])

    connect(dst_ip, dst_port)
