import argparse
import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for item in answered:
        client_dict = {"ip": item[1].psrc, "mac": item[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def print_result(result_list):
    print("IP:\t\t\tMAC:")
    print("----------------------------------------")
    for client in result_list:
        print(client["ip"]+"\t\t"+client["mac"])

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="ip", help="Enter the desired ip range to scan")
    args = parser.parse_args()
    if not args.ip:
        parser.error("Please enter an IP address range to scan using '-t'")
    return args

args = get_arguments()
scan_result = scan(args.ip)
print_result(scan_result)
