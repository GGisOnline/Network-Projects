import argparse
import pyshark
import matplotlib.pyplot as plt
from collections import defaultdict
from datetime import datetime
import os

RESULTS_FOLDER = "Results/PlotResults"


'''
---------------------------------------------------------------------------------------------------------------------------------------------------

Functions for the capture, ploting and generating
-------------------------------------------------

- CaptureLoader(packetpath) -> Loading the file given as arg. DO NOT TOUCH !!!
- def generateResults(results, type, nameCapture):
    with open("Results/AnalyzerResults/{}_{}.txt".format(type, nameCapture), "w") as file:
        for query, response in results.items():
            file.write(f"{query} -> {response}\n")
    print("Results have been saved in Results/{}_{}.txt".format(type, nameCapture))

- plot_dns_resolutions(dns_resolutions) -> Return a plot containing DNS proportion
- plot_ip_packets(ipv4_count, ipv6_count) -> Return a plot containing IP packets version proportion
- plot_transport_protocols(tcp_count, udp_count, quic_count) -> Return a plot containing transport protocols and their proportion
---------------------------------------------------------------------------------------------------------------------------------------------------
'''

def CaptureLoader(packetpath):
    return pyshark.FileCapture(packetpath)


def plot_dns_resolutions(dns_resolutions):
    x_values = list(dns_resolutions.keys())
    y_values = list(dns_resolutions.values())

    plt.figure(figsize=(10, 6))
    plt.plot(x_values, y_values, marker='o', linestyle='-')
    plt.title('Évolution du nombre de résolutions DNS au fil du temps')
    plt.xlabel('Temps')
    plt.ylabel('Nombre de résolutions DNS')
    plt.xticks(rotation=45)
    plt.tight_layout()

    plt.savefig(os.path.join(RESULTS_FOLDER, "DNSgraph.png"))
    plt.show()

def plot_ip_packets(ipv4_count, ipv6_count):
    labels = ['IPv4', 'IPv6']
    counts = [ipv4_count, ipv6_count]

    plt.figure(figsize=(8, 6))
    plt.bar(labels, counts, color=['blue', 'green'])
    plt.title('Nombre de paquets IPv4 et IPv6')
    plt.xlabel('Type de paquet')
    plt.ylabel('Nombre de paquets')

    plt.savefig(os.path.join(RESULTS_FOLDER, "IPgraph.png"))
    plt.show()

def plot_transport_protocols(tcp_count, udp_count):
    labels = ['TCP', 'UDP']
    counts = [tcp_count, udp_count]

    plt.figure(figsize=(8, 6))
    plt.pie(counts, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.title('Proportion des protocoles de transport utilisés')
    plt.axis('equal')

    plt.savefig(os.path.join(RESULTS_FOLDER, "PROTOCOLgraph.png"))
    plt.show()



'''
---------------------------------------------------------------------------------------------------------------------------------------------------

DNS
---

- count_dns_resolutions(MyCapture) -> Return all value about DNS packets for ploting.

Feel free to edit it if needed.
---------------------------------------------------------------------------------------------------------------------------------------------------

'''

def count_dns_resolutions(MyCapture):
    dns_resolutions = {}

    for pkt in MyCapture:
        if 'dns' in pkt:
            dns_time = pkt.sniff_time
            if dns_time in dns_resolutions:
                dns_resolutions[dns_time] += 1
            else:
                dns_resolutions[dns_time] = 1
    MyCapture.close()

    return dns_resolutions



'''
---------------------------------------------------------------------------------------------------------------------------------------------------

IP
--

- count_ip_packets(MyCapture) -> Return count of IPV4 and IPV6 packets for ploting.

Feel free to edit it if needed.
---------------------------------------------------------------------------------------------------------------------------------------------------

'''
def count_ip_packets(MyCapture):
    ipv4_count = 0
    ipv6_count = 0

    for pkt in MyCapture:
        if 'IP' in pkt:
            ipv4_count += 1
        elif 'IPv6' in pkt:
            ipv6_count += 1
    MyCapture.close()

    return ipv4_count, ipv6_count



'''
---------------------------------------------------------------------------------------------------------------------------------------------------

PROTOCOL
--------

- count_transport_protocols(MyCapture) -> Return count of TCP and UDP protocol seen for ploting.

Feel free to edit it if needed.
---------------------------------------------------------------------------------------------------------------------------------------------------

'''

def count_transport_protocols(MyCapture):
    tcp_count = 0
    udp_count = 0

    for pkt in MyCapture:
        if 'tcp' in pkt:
            tcp_count += 1
        elif 'udp' in pkt:
            udp_count += 1
    MyCapture.close()

    return tcp_count, udp_count







'''
-----------
Parser Zone
-----------

    Parser made for better interaction and flexibility.
    Note that other arguments can be added if you want. Just follow these exemples given below.

'''

def main():

    MyParser = argparse.ArgumentParser(description="Packet Plot Analyzer")
    
    MyParser.add_argument("packet_path", type=str, help="Path of the packet you would like to analyze")
    MyParser.add_argument("--dns", action="store_true", help="Ploting DNS analysis")
    MyParser.add_argument("--ip", action="store_true", help="Ploting IP anaylsis")
    MyParser.add_argument("--protocol", action="store_true", help="Ploting protocol analysis")

    MyArguments = MyParser.parse_args()

    MyCapture = CaptureLoader(MyArguments.packet_path)

    if MyArguments.dns:

        DNSResults = count_dns_resolutions(MyCapture)
        plot_dns_resolutions(DNSResults)

    if MyArguments.ip:

        ipv4Results, ipv6Results = count_ip_packets(MyCapture)
        plot_ip_packets(ipv4Results, ipv6Results)

    if MyArguments.protocol:
        tcpResults, udpResults = count_transport_protocols(MyCapture)
        plot_transport_protocols(tcpResults, udpResults)


if __name__ == "__main__":
    main()