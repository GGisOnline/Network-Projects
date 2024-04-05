import argparse
import pyshark
import socket
import os

'''
---------------------------------------------------------------------------------------------------------------------------------------------------

Functions for the capture & conversion
--------------------------------------

- CaptureLoader(packetpath) -> Loading the file given as arg. DO NOT TOUCH !!!

- tls_version_to_str(hex_versions) -> Translate hexadecimal versions of TLS into string
- tls_record_version_to_str(hex_versions) -> Translate hexadecimal versions of record TLS into string
- tls_handshake_type_to_str(hex_versions) -> Translate hexadecimal versions of handshake type TLS into string
---------------------------------------------------------------------------------------------------------------------------------------------------
'''

def CaptureLoader(packetpath):
    return pyshark.FileCapture(packetpath)

#Helped with ChatGPT for this one
def tls_version_to_str(hex_versions):
    version_names = {
        '0x0300': 'SSL 3.0',
        '0x0301': 'TLS 1.0',
        '0x0302': 'TLS 1.1',
        '0x0303': 'TLS 1.2',
        '0x0304': 'TLS 1.3',
        'N/A': 'N/A',
    }
    
    #Convertit chaque version hexadécimale en son nom correspondant, si disponible.
    TLSVersionTranslated = [version_names.get(hex_versions)]
    
    return TLSVersionTranslated

#Helped with ChatGPT for this one
def tls_record_version_to_str(hex_versions):
    version_names = {
        '0x0300': 'SSL 3.0',
        '0x0301': 'TLS 1.0',
        '0x0302': 'TLS 1.1',
        '0x0303': 'TLS 1.2',
        '0x0304': 'TLS 1.3',
        'N/A': 'N/A',
    }
    
    #Convertit chaque version hexadécimale en son nom correspondant, si disponible.
    RecordVersionTranslated = [version_names.get(hex_versions)]
    
    return RecordVersionTranslated

#Helped with ChatGPT for this one
def tls_handshake_type_to_str(hex_versions):
    version_names = {
        '1': 'ClientHello',
        '2': 'ServerHello',
        '11': 'Certificate',
        '12': 'ServerKeyExchange',
        '14': 'ServerHelloDone',
        '16': 'ClientKeyExchange',
        '20': 'Finished',
        'N/A': 'N/A',
    }
    
    #Convertit chaque version hexadécimale en son nom correspondant, si disponible.
    HanshakeTypeTranslated = [version_names.get(hex_versions)]
    
    return HanshakeTypeTranslated

def generateResults(results, type, nameCapture):
    with open("Results/AnalyzerResults/{}_{}.txt".format(type, nameCapture), "w") as file:
        for query, response in results.items():
            file.write(f"{query} -> {response}\n")
    print("Results have been saved in Results/{}_{}.txt".format(type, nameCapture))



'''
---------------------------------------------------------------------------------------------------------------------------------------------------

DNS
---

- CaptureDNS(capture) -> Capture all packets in pcap/pcapng file given and analyze DNS.

Feel free to edit it if needed.
---------------------------------------------------------------------------------------------------------------------------------------------------

'''
def CaptureDNS(capture, sourceaddress):
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

        if not sourceaddress or SourceAddress==sourceaddress:
            if packet.highest_layer == 'DNS' and hasattr(packet.dns, 'qry_name'):
                query_name = packet.dns.qry_name

                if hasattr(packet.dns, 'a'):
                    response_address = packet.dns.a
                else:
                    response_address = 'N/A'
                
                dns_queries[query_name] = response_address
    
    return dns_queries




'''
---------------------------------------------------------------------------------------------------------------------------------------------------

NET Layer
---------

- CaptureNetLayer(capture) -> Counting number of packets for each different source IP address.

Feel free to edit it if needed.
---------------------------------------------------------------------------------------------------------------------------------------------------
'''
def CaptureNetLayer(capture, sourceaddress):
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


        if not sourceaddress or SourceAddress==sourceaddress:
            flow = (SourceAddress, DestinationAddress)

            if flow not in ip_addresses:
                ip_addresses[flow]=0
            
            ip_addresses[flow]+=1

    return ip_addresses




'''
---------------------------------------------------------------------------------------------------------------------------------------------------

TLS Version
-----------

- CaptureTLSVersion(capture) -> Getting information for each TLS Packets in the file given.

Feel free to edit it if needed.
---------------------------------------------------------------------------------------------------------------------------------------------------
'''
def CaptureTLSVersion(capture, sourceaddress):
    Results={}
    for packet in capture:

        TLSHandshakeVersion="N/A"
        TLSRecordVersion="N/A"
        TLSHandshakeType="N/A"

        if 'IP' in packet:
            SourceAddress = packet.ip.src
            DestinationAddress = packet.ip.dst
        elif 'IPv6' in packet:
            SourceAddress = packet.ipv6.src
            DestinationAddress = packet.ipv6.dst
        else:
            continue


        if not sourceaddress or SourceAddress==sourceaddress:
            if 'TLS' in packet:
                if hasattr(packet.tls, 'handshake_version'):
                    TLSHandshakeVersion = packet.tls.handshake_version
                if hasattr(packet.tls, 'record_version'):
                    TLSRecordVersion = packet.tls.record_version
                if hasattr(packet.tls, 'handshake_type'):
                    TLSHandshakeType = packet.tls.handshake_type

                TLSVersionTranslated=tls_version_to_str(TLSHandshakeVersion)
                TLSRecordVersionTranslated=tls_record_version_to_str(TLSRecordVersion)
                TLSHandshakeTypeTranslated=tls_handshake_type_to_str(TLSHandshakeType)

                TLSResults = {
                'handshake_version': TLSVersionTranslated,
                'record_version': TLSRecordVersionTranslated,
                'handshake_type': TLSHandshakeTypeTranslated
                }

                flow = (SourceAddress, DestinationAddress)
                    
                if flow not in Results:
                    Results[flow] = [TLSResults]
                else:
                    if TLSResults not in Results[flow]:
                            Results[flow].append(TLSResults)

    return Results
                



'''
---------------------------------------------------------------------------------------------------------------------------------------------------

Complete Capture
----------------

- Capture(capture) -> Capture all packets in the pcap/pcapng file given and give all informations about them.
- CaptureCustom(capture, sourceaddress) -> Capture specific packet given in the pcap/pcapng file given and give all informations about it.

Feel free to edit it if needed.
---------------------------------------------------------------------------------------------------------------------------------------------------
'''

def Capture(capture, sourceaddress):

    Results={}

    for packet in capture:
        
        TLSHandshakeVersion="N/A"
        TLSRecordVersion="N/A"
        TLSHandshakeType="N/A"

        if 'IP' in packet:
            SourceAddress = packet.ip.src
            DestinationAddress = packet.ip.dst
        elif 'IPv6' in packet:
            SourceAddress = packet.ipv6.src
            DestinationAddress = packet.ipv6.dst
        else:
            continue


        if not sourceaddress or SourceAddress==sourceaddress:
            flow = (SourceAddress, DestinationAddress)

            if flow not in Results:
                Results[flow]={
                'Counter': 0,
                'DNS Results': [],
                'TLS Results': [],
            }

            Results[flow]['Counter'] += 1

            if packet.highest_layer == 'DNS' and hasattr(packet.dns, 'qry_name'):
                    query_name = packet.dns.qry_name

                    if hasattr(packet.dns, 'a'):
                        response_address = packet.dns.a
                    else:
                        response_address = 'N/A'

                    DNSResults = {
                        'query_name': query_name,
                        'response_address': response_address,
                    }
                    
                    Results[flow]['DNS Results'].append(DNSResults)

            if 'TLS' in packet:
                if hasattr(packet.tls, 'handshake_version'):
                    TLSHandshakeVersion = packet.tls.handshake_version
                if hasattr(packet.tls, 'record_version'):
                    TLSRecordVersion = packet.tls.record_version
                if hasattr(packet.tls, 'handshake_type'):
                    TLSHandshakeType = packet.tls.handshake_type

                TLSVersionTranslated=tls_version_to_str(TLSHandshakeVersion)
                TLSRecordVersionTranslated=tls_record_version_to_str(TLSRecordVersion)
                TLSHandshakeTypeTranslated=tls_handshake_type_to_str(TLSHandshakeType)

                TLSResults = {
                'handshake_version': TLSVersionTranslated,
                'record_version': TLSRecordVersionTranslated,
                'handshake_type': TLSHandshakeTypeTranslated
                }
            
                Results[flow]['TLS Results'].append(TLSResults)

    return Results
        


'''
-----------
Parser Zone
-----------

    Parser made for better interaction and flexibility.
    Note that other arguments can be added if you want. Just follow these exemples given below.

'''

DEBUG_MODE = False

def main():

    global DEBUG_MODE

    MyParser = argparse.ArgumentParser(description="Packet Analyzer")
    
    MyParser.add_argument("packet_path", type=str, help="Path of the packet you would like to analyze")
    MyParser.add_argument("--dns", action="store_true", help="Analyzing DNS requests only")
    MyParser.add_argument("--netlayer", action="store_true", help="Analyzing the network layer")
    MyParser.add_argument("--tls", action="store_true", help="Analyze TLS version/handshake on given packets")
    MyParser.add_argument("--glob", action="store_true", help="Global analyze of file given")
    MyParser.add_argument("-D", "--debug", action="store_true", help="Enable debug mode")

    MyArguments = MyParser.parse_args()
    DEBUG_MODE = MyArguments.debug

    nameCapture = os.path.splitext(os.path.basename(MyArguments.packet_path))[0]
    MyCapture = CaptureLoader(MyArguments.packet_path)

    if DEBUG_MODE:
        print(MyCapture)

    if MyArguments.dns:
        
        '''
        if DEBUG_MODE:
            print(CaptureDNS(MyCapture))
        '''

        SourceAddress = input("Do you need a specific source address ? Yes/No: ")
        gotaddress=False

        if SourceAddress in ["Yes", "yes", "Y", "y"]:
            SourceAddress = input("Please enter the source address you want to be recorded: ")

            try:
                socket.inet_aton(SourceAddress)
            except OSError:
                try:
                    socket.inet_pton(socket.AF_INET6, SourceAddress)
                except OSError:
                    print("The address entered is not valid. Please try again.")
        
        else:
            SourceAddress = None

        DNSResults = CaptureDNS(MyCapture, SourceAddress)

        if (DNSResults):
            generateResults(DNSResults, "DNS", nameCapture)
        else:
            print("No results found.")

    
    if MyArguments.netlayer:

        '''
        if DEBUG_MODE:
            print(CaptureNetLayer(MyCapture))
        '''

        SourceAddress = input("Do you need a specific source address ? Yes/No: ")
        gotaddress=False

        if SourceAddress in ["Yes", "yes", "Y", "y"]:
            SourceAddress = input("Please enter the source address you want to be recorded: ")
            
            try:
                socket.inet_aton(SourceAddress)
            except OSError:
                try:
                    socket.inet_pton(socket.AF_INET6, SourceAddress)
                except OSError:
                    print("The address entered is not valid. Please try again.")
        
        else:
            SourceAddress = None

        
        NLResults = CaptureNetLayer(MyCapture, SourceAddress)

        if (NLResults):
            generateResults(NLResults, "NL", nameCapture)
        else:
            print("No results found.")


    if MyArguments.tls:
        
        '''
        if DEBUG_MODE:
            print(CaptureTLSVersion(MyCapture))
        '''

        SourceAddress = input("Do you need a specific source address ? Yes/No: ")

        if SourceAddress in ["Yes", "yes", "Y", "y"]:
            SourceAddress = input("Please enter the source address you want to be recorded: ")
            
            try:
                socket.inet_aton(SourceAddress)
            except OSError:
                try:
                    socket.inet_pton(socket.AF_INET6, SourceAddress)
                except OSError:
                    print("The address entered is not valid. Please try again.")

        else:
            SourceAddress = None


        
        TLSResults=CaptureTLSVersion(MyCapture, SourceAddress)

        if (TLSResults):
            generateResults(TLSResults, "TLS", nameCapture)
        else:
            print("No results found.")
    

    if MyArguments.glob:

        '''
        if DEBUG_MODE:
            print(Capture(MyCapture))
        '''
        
        SourceAddress = input("Do you need a specific source address ? Yes/No: ")

        if SourceAddress in ["Yes", "yes", "Y", "y"]:
            SourceAddress = input("Please enter the source address you want to be recorded: ")
            
            try:
                socket.inet_aton(SourceAddress)
            except OSError:
                try:
                    socket.inet_pton(socket.AF_INET6, SourceAddress)
                except OSError:
                    print("The address entered is not valid. Please try again.")

        else:
            SourceAddress = None


        GlobalResults=Capture(MyCapture, SourceAddress)

        if (GlobalResults):
            generateResults(GlobalResults, "Global", nameCapture)
        else:
            print("No results found.")


if __name__ == "__main__":
    main()
