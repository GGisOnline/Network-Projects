
import argparse
import pyshark
import socket



'''
-------------------------
Function for the capture
-------------------------

    Loading the file given as arg. DO NOT TOUCH
'''

def CaptureLoader(packetpath):
    return pyshark.FileCapture(packetpath)




'''
---
DNS
---

- CaptureDNS(capture) -> Capture all packets in pcap/pcapng file given and analyze DNS.
- CaptureDNSCustom(capture, sourceaddress) -> Capture all packets having the source ip address given in pcap/pcapng file given and analyze DNS.

Feel free to edit it.

'''
def CaptureDNS(capture):
    dns_queries =  {}
    for packet in capture:
        if 'IP' in packet:
            SourceAddress=packet.ip.src
            DestinationAddress=packet.ip.dst
        elif 'IPv6' in packet:
            SourceAddress = packet.ipv6.src
            DestinationAddress = packet.ipv6.dst
        else:
            continue

        if packet.highest_layer == 'DNS' and hasattr(packet.dns, 'qry_name'):
            query_name = packet.dns.qry_name

            if hasattr(packet.dns, 'a'):
                response_address = packet.dns.a
            else:
                response_address = 'N/A'
            
            dns_queries[query_name] = response_address
    
    return dns_queries

def CaptureDNSCustom(capture, sourceaddress):
    dns_queries =  {}
    for packet in capture:
        if 'IP' in packet:
            SourceAddress=packet.ip.src
            DestinationAddress=packet.ip.dst
        elif 'IPv6' in packet:
            SourceAddress = packet.ipv6.src
            DestinationAddress = packet.ipv6.dst
        else:
            continue

        if SourceAddress==sourceaddress:
            if packet.highest_layer == 'DNS' and hasattr(packet.dns, 'qry_name'):
                query_name = packet.dns.qry_name

                if hasattr(packet.dns, 'a'):
                    response_address = packet.dns.a
                else:
                    response_address = 'N/A'
                
                dns_queries[query_name] = response_address
    
    return dns_queries



'''
NET Layer

- CaptureNetayer(capture) -> 
- CaptureNetLayerCustom(capture, sourceaddress) -> 
'''
def CaptureNetLayer(capture):
    ip_addresses={}
    for packet in capture:
        if 'IP' in packet:
            SourceAddress=packet.ip.src
            DestinationAddress=packet.ip.dst
        elif 'IPv6' in packet:
            SourceAddress = packet.ipv6.src
            DestinationAddress = packet.ipv6.dst
        else:
            continue

        flow = (SourceAddress, DestinationAddress)

        if flow not in ip_addresses:
            ip_addresses[flow]=0
        
        ip_addresses[flow]+=1

    return ip_addresses

def CaptureNetLayerCustom(capture, sourceaddress):
    ip_addresses={}
    for packet in capture:
        if 'IP' in packet:
            SourceAddress=packet.ip.src
            DestinationAddress=packet.ip.dst
        elif 'IPv6' in packet:
            SourceAddress = packet.ipv6.src
            DestinationAddress = packet.ipv6.dst
        else:
            continue

        if SourceAddress==sourceaddress:
            flow = (SourceAddress, DestinationAddress)

            if flow not in ip_addresses:
                ip_addresses[flow]=0
            
            ip_addresses[flow]+=1
        else:
            continue

    return ip_addresses



'''
TODO : SOLVE BUGS
'''

def CaptureTLS(capture):
    for packet in capture:
        if 'IP' in packet:
            SourceAddress = packet.ip.src
        elif 'IPv6' in packet:
            SourceAddress = packet.ipv6.src
        else:
            continue
                
        if 'TLS' in packet:
            if hasattr(packet.tls, 'handshake_version'):
                tls_handshake_version = packet.tls.handshake_version
                print(f"Packet {packet.number}: TLS Handshake Version {tls_handshake_version}")

                if hasattr(packet.tls, 'handshake_type'):
                    handshake_type = packet.tls.handshake_type
                    print(f"Handshake Type: {handshake_type}")
                
            else:
                tls_record_version = packet.tls.record_version
                print(f"Packet {packet.number}: TLS Record Version (fallback) {tls_record_version}")        

def CaptureTLSCustom(capture, sourceaddress):
    for packet in capture:
        if 'IP' in packet:
            SourceAddress = packet.ip.src
        elif 'IPv6' in packet:
            SourceAddress = packet.ipv6.src
        else:
            continue

        if SourceAddress == sourceaddress:
            if 'TLS' in packet:
                if hasattr(packet.tls, 'handshake_version'):
                    tls_handshake_version = packet.tls.handshake_version
                    print(f"Packet {packet.number}: TLS Handshake Version {tls_handshake_version}")

                    if hasattr(packet.tls, 'handshake_type'):
                        handshake_type = packet.tls.handshake_type
                        print(f"Handshake Type: {handshake_type}")
                    
                else:
                    tls_record_version = packet.tls.record_version
                    print(f"Packet {packet.number}: TLS Record Version (fallback) {tls_record_version}")



'''
TODO: SOLVE BUGS


def CustomCapture(capture, sourceaddress):
    for packet in capture:
        if 'IP' in packet:
            ip_src = packet.ip.src
        elif 'IPv6' in packet:
            ip_src = packet.ipv6.src
        else:
            continue
            

        if ip_src == sourceaddress:
            print(f"Packet {packet.number}: SRC {ip_src} -> DST {packet.ip.dst}")
                
            if packet.highest_layer == 'DNS':
                print(f"DNS Query: {packet.dns.qry_name} -> Type: {packet.dns.qry_type}")
                
            if 'TCP' in packet:
                print(f"TCP Source Port: {packet.tcp.srcport}, Destination Port: {packet.tcp.dstport}")
            elif 'UDP' in packet:
                print(f"UDP Source Port: {packet.udp.srcport}, Destination Port: {packet.udp.dstport}")
        
        else:
            print(f"Packet {packet.number}: SRC {ip_src} -> DST {packet.ip.dst}")
                
            if packet.highest_layer == 'DNS':
                print(f"DNS Query: {packet.dns.qry_name} -> Type: {packet.dns.qry_type}")
                
            if 'TCP' in packet:
                print(f"TCP Source Port: {packet.tcp.srcport}, Destination Port: {packet.tcp.dstport}")
            elif 'UDP' in packet:
                print(f"UDP Source Port: {packet.udp.srcport}, Destination Port: {packet.udp.dstport}")
'''


'''
-----------
Parser Zone
-----------

    Parser made for better interaction and flexibility.
    Note that other arguments can be added if you want. Just follow these exemples given below.

'''

def main():
    MyParser = argparse.ArgumentParser(description="Packet Analyzer")
    
    MyParser.add_argument("packet_path", type=str, help="Path of the packet you would like to analyze")
    MyParser.add_argument("--dns", action="store_true", help="Analyzing DNS requests only")
    MyParser.add_argument("--netlayer", action="store_true", help="Analyzing the network layer")
    MyParser.add_argument("--tls", action="store_true", help="Analyze TLS version/handshake on given packets")
    MyParser.add_argument("--custom", action="store_true", help="Give a complete checkup based on custom source IP address")

    MyArguments = MyParser.parse_args()

    MyCapture = CaptureLoader(MyArguments.packet_path)

    #DEBUG MODE
    #print(MyCapture)

    
    if MyArguments.dns:

        #DEBUG MODE
        #print(CaptureDNS(MyCapture))

        SourceAddress = input("Do you need a specific source adress ? Yes/No: ")
        if SourceAddress == "Yes" or SourceAddress == "yes" or SourceAddress == "Y" or SourceAddress == "y":
            SourceAddress = input("Please enter the source adress you want to be recorded: ")

            try:
                socket.inet_aton(SourceAddress)
                gotaddress=True
            except OSError:
                try:
                    socket.inet_pton(socket.AF_INET6, SourceAddress)
                    gotaddress=True
                except OSError:
                    print("The address entered is not valid. Please try again.")

        else:
            gotaddress=False

        if(gotaddress):
            DNSResults = CaptureDNSCustom(MyCapture, SourceAddress)
        else:
            DNSResults = CaptureDNS(MyCapture)

        print('Here are the DNS results: ')
        for query, response in DNSResults.items():
            print(f"{query} -> {response}")

    
    
    if MyArguments.netlayer:

        #DEBUG MODE
        #print(CaptureNetLayer(MyCapture))

        SourceAddress = input("Do you need a specific source adress ? Yes/No: ")
        if SourceAddress == "Yes" or SourceAddress == "y" or SourceAddress == "yes" or SourceAddress == "Y":
            SourceAddress = input("Please enter the source adress you want to be recorded: ")
            
            try:
                socket.inet_aton(SourceAddress)
                gotaddress=True
            except OSError:
                try:
                    socket.inet_pton(socket.AF_INET6, SourceAddress)
                    gotaddress=True
                except OSError:
                    print("The address entered is not valid. Please try again.")

        else:
            gotaddress=False

        if(gotaddress):
            NLResults = CaptureNetLayerCustom(MyCapture, SourceAddress)
        else:
            NLResults = CaptureNetLayer(MyCapture)

        print("Here are the results of the network layer: ")
        for flow, count in NLResults.items():
            print(f"{flow}: {count} paquets")


    if MyArguments.tls:
        
        #DEBUG MODE
        #print(CaptureNetLayer(MyCapture))

        SourceAddress = input("Do you need a specific source adress ? Yes/No: ")
        if SourceAddress == "Yes" or SourceAddress == "y" or SourceAddress == "yes" or SourceAddress == "Y":
            SourceAddress = input("Please enter the source adress you want to be recorded: ")
            
            try:
                socket.inet_aton(SourceAddress)
                gotaddress=True
            except OSError:
                try:
                    socket.inet_pton(socket.AF_INET6, SourceAddress)
                    gotaddress=True
                except OSError:
                    print("The address entered is not valid. Please try again.")

        else:
            gotaddress=False

        if(gotaddress):
            TLSResults=CaptureTLSCustom(MyCapture, SourceAddress)
        else:
            TLSResults=CaptureTLS(MyCapture)

        print("Here are the TLS results: ")
        print(TLSResults)
   
    
    if MyArguments.custom:

        #DEBUG MODE
        #print(CaptureNetLayer(MyCapture))

        SourceAddress = input("Do you need a specific source adress ? Yes/No: ")
        if SourceAddress == "Yes" or SourceAddress == "y" or SourceAddress == "yes" or SourceAddress == "Y":
            SourceAddress = input("Please enter the source adress you want to be recorded: ")
            
            try:
                socket.inet_aton(SourceAddress)
                gotaddress=True
            except OSError:
                try:
                    socket.inet_pton(socket.AF_INET6, SourceAddress)
                    gotaddress=True
                except OSError:
                    print("The address entered is not valid. Please try again.")
                    
        else:
            gotaddress=False

        if(gotaddress):
            CustomCapture(MyCapture, SourceAddress)






if __name__ == "__main__":
    main()