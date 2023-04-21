#!/usr.bin.env python
import scapy.all as scapy
import optparse

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1)[0]
    
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
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="ip", help="Enter the desired ip range to scan")
    (options, arguments) = parser.parse_args()
    if not options.ip:
        print("Please enter an ip address using '-t'")
        exit()
    else:
        return options


options = get_arguments()
scan_result = scan(options.ip)
print_result(scan_result)
