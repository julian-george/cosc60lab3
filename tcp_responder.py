import signal
import sys
import threading
from time import sleep
from scapy.all import TCP, IP, send, sniff

from shared import setup_iptables, cleanup_iptables, get_default_interface_ip


SERVER_IP = get_default_interface_ip()
SERVER_PORT = 8080
HTTP_RESPONSE_FILE = "http-jpg-response.txt"
MAX_SEGMENT_SIZE = 1460
RETRANS_TIME = 2

connections = {}
connections_lock = threading.Lock()

# Load the HTTP response
with open(HTTP_RESPONSE_FILE, "rb") as f:
    http_response = f.read()


def print_header(packet):
    if TCP in packet:
        tcp_layer = packet[TCP]
        print(f"Source Port: {tcp_layer.sport}")
        print(f"Destination Port: {tcp_layer.dport}")
        print(f"Sequence Number: {tcp_layer.seq}")
        print(f"Acknowledgment Number: {tcp_layer.ack}")
        print(f"Data Offset: {tcp_layer.dataofs * 4} bytes")
        print(f"Flags: {tcp_layer.flags}")
        print(f"Window Size: {tcp_layer.window}")
        print(f"Checksum: {tcp_layer.chksum}")
        print(f"Urgent Pointer: {tcp_layer.urgptr}")


def send_chunk(conn_id, chunk, seq_num, ack_num):
    with connections_lock:
        if conn_id not in connections:
            return
    tcp_packet = (
        IP(src=SERVER_IP, dst=conn_id[0])
        / TCP(
            sport=SERVER_PORT,
            dport=conn_id[1],
            seq=seq_num,
            ack=ack_num,
            flags="PA",
        )
        / chunk
    )
    send(tcp_packet, verbose=False)
    sleep(RETRANS_TIME)
    is_done = True
    with connections_lock:
        if conn_id in connections and seq_num in connections[conn_id]["sent_data"]:
            is_done = False
    if not is_done:
        send_chunk(conn_id, chunk, seq_num, ack_num)


def send_rst(conn_id):
    (client_ip, client_port) = conn_id
    rst = IP(src=SERVER_IP, dst=client_ip) / TCP(
        sport=SERVER_PORT,
        dport=client_port,
        seq=0,
        ack=0,
        flags="R",
    )
    send(rst, verbose=False)


# Define a callback function to process the packets
def packet_callback(packet):
    if TCP not in packet or packet[TCP].dport != SERVER_PORT:
        return

    client_ip = packet[IP].src
    client_port = packet[TCP].sport
    conn_id = (client_ip, client_port)

    if conn_id not in connections:
        with connections_lock:
            connections[conn_id] = {"seq": 1000, "ack": 0, "sent_data": set()}

    with connections_lock:
        # read-only var. to edit, use lock and modify connections
        state = connections[conn_id]
    print(
        f"Received packet from {client_ip}:{client_port} with flags {packet[TCP].flags}"
    )

    if "S" in packet[TCP].flags:  # SYN
        # print_header(packet)
        state["ack"] = packet.seq + 1
        syn_ack = IP(src=SERVER_IP, dst=client_ip) / TCP(
            sport=SERVER_PORT,
            dport=client_port,
            seq=state["seq"],
            ack=state["ack"],
            flags="SA",
        )
        send(syn_ack)
        with connections_lock:
            connections[conn_id]["seq"] += 1
        print("Sent SYN-ACK to:", client_ip)
    elif "F" in packet[TCP].flags and "A" in packet[TCP].flags:
        ack = IP(src=SERVER_IP, dst=packet[IP].src) / TCP(
            sport=SERVER_PORT,
            dport=packet[TCP].sport,
            seq=packet[TCP].ack,
            ack=packet[TCP].seq + 1,
            flags="A",
        )
        send(ack, verbose=False)
        fin_ack = IP(src=SERVER_IP, dst=packet[IP].src) / TCP(
            sport=SERVER_PORT,
            dport=packet[TCP].sport,
            seq=packet[TCP].ack,
            ack=packet[TCP].seq + 1,
            flags="FA",
        )
        send(fin_ack, verbose=False)
        print("Sent FIN-ACK to:", packet[IP].src)

        with connections_lock:
            del connections[conn_id]
    elif "A" in packet[TCP].flags:  # ACK
        if state["ack"] == packet[TCP].seq and len(state["sent_data"]) == 0:
            print("Resending after")
            print_header(packet)

            for i in range(0, len(http_response), MAX_SEGMENT_SIZE):
                seq_num = i + state["seq"]
                x = threading.Thread(
                    target=send_chunk,
                    args=(
                        conn_id,
                        http_response[i : i + MAX_SEGMENT_SIZE],
                        seq_num,
                        state["ack"],
                    ),
                )
                x.start()
                with connections_lock:
                    connections[conn_id]["sent_data"].add(seq_num)
                sleep(0.01)
            with connections_lock:
                connections[conn_id]["seq"] += len(http_response)
        else:
            ack_num = packet[TCP].ack
            with connections_lock:
                connections[conn_id]["sent_data"] = set(
                    filter(
                        lambda s_num: ack_num < s_num, connections[conn_id]["sent_data"]
                    ),
                )
                connections[conn_id]["ack"] = packet[TCP].seq + 1
    elif "R" in packet[TCP].flags:
        print("Ending connection from", conn_id)
        with connections_lock:
            del connections[conn_id]


def signal_handler(sig, frame):
    print("Exiting and cleaning up iptables...")
    cleanup_iptables(SERVER_PORT)
    sys.exit(0)


if __name__ == "__main__":
    setup_iptables(SERVER_PORT)
    signal.signal(signal.SIGINT, signal_handler)
    print(f"Listening for TCP packets on {SERVER_IP}:{SERVER_PORT}...")
    sniff(filter=f"tcp and port {SERVER_PORT}", prn=packet_callback)
