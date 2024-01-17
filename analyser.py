from scapy.all import *
import os
import ipaddress
import argparse

def is_external_ip(ip, local_network):
    return ipaddress.ip_address(ip) not in local_network

def filter_and_log_connections(input_pcap, local_network, miner_log_path, warning_log_path):
    packets = rdpcap(input_pcap)
    logged_ips = set()  # Set to track logged IPs

    with open(miner_log_path, 'a') as miner_log, open(warning_log_path, 'a') as warning_log:
        for packet in packets:
            if IP in packet and TCP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                if hasattr(packet[TCP], 'load'):
                    payload = packet[TCP].payload.load.decode('utf-8', 'ignore')

                    # Check for miner
                    if payload and ("agent" in payload or "XMRig" in payload):
                        miner_log.write(f"Miner detected! Source IP: {src_ip}, Destination IP: {dst_ip}\n")

                    # Log warning for external IPs not identified as miners
                    elif (is_external_ip(src_ip, local_network) and src_ip not in logged_ips) or \
                         (is_external_ip(dst_ip, local_network) and dst_ip not in logged_ips):
                        external_ip = src_ip if is_external_ip(src_ip, local_network) else dst_ip
                        warning_log.write(f"External IP: {external_ip}, Other IP: {dst_ip if external_ip == src_ip else src_ip}\n")
                        logged_ips.add(external_ip)  # Add to set to prevent re-logging

def process_all_pcaps_in_folder(folder_path, local_network):
    analyzed_folder = os.path.join(os.getcwd(), "analyzed")
    os.makedirs(analyzed_folder, exist_ok=True)  # Create 'analyzed' folder in current directory if it doesn't exist

    miner_log_path = os.path.join(analyzed_folder, "miner_connection.log")
    warning_log_path = os.path.join(analyzed_folder, "warning_connection.log")

    for filename in os.listdir(folder_path):
        if filename.endswith('.pcap') or filename.endswith('.pcapng'):
            print(f"Processing file: {filename}")
            input_pcap = os.path.join(folder_path, filename)
            filter_and_log_connections(input_pcap, local_network, miner_log_path, warning_log_path)

def main():
    parser = argparse.ArgumentParser(description='Analyze PCAP files for miner and warning connections.')
    parser.add_argument('folder_path', help='Path to the folder containing PCAP files to analyze')

    args = parser.parse_args()
    folder_path = args.folder_path
    local_network = ipaddress.ip_network('192.168.1.0/24', strict=False)

    process_all_pcaps_in_folder(folder_path, local_network)

if __name__ == "__main__":
    main()
