
import argparse
import pyshark


'''
-------------------------
Functions for the capture
-------------------------

    Feel free to add other functions if needed.
'''

#Loading the file given as arg. DO NOT TOUCH !
def CaptureLoader(packetpath):
    return pyshark.FileCapture(packetpath)


#Function analyzing DNS requests only. Feel free to edit.
def CaptureDNS(capture):
    dns_queries =  {}
    for packet in capture:
        if packet.highest_layer == 'DNS' and hasattr(packet.dns, 'qry_name'):
            query_name = packet.dns.qry_name

            if hasattr(packet.dns, 'a'):
                response_adress = packet.dns.a
            else:
                response_adress = 'N/A'
            
            dns_queries[query_name] = response_adress
    
    return dns_queries

#Function analysing IP adresses (sources and destination)
def CaptureNetLayer(capture):
    ip_adresses={}
    for packet in capture:
        if 'IP' in packet:
            SourceAdress=packet.ip.src
            DestinationAdress=packet.ip.dst

            flow = (SourceAdress, DestinationAdress)

            if flow not in ip_adresses:
                ip_adresses[flow]=0
            
            ip_adresses[flow]+=1

    return ip_adresses


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

    MyArguments = MyParser.parse_args()

    MyCapture = CaptureLoader(MyArguments.packet_path)

    #DEBUG MODE
    #print(MyCapture)

    if MyArguments.dns:

        #DEBUG MODE
        #print(CaptureDNS(MyCapture))

        DNSResults = CaptureDNS(MyCapture)

        print('Here are the DNS results :')
        for query, response in DNSResults.items():
            print(f"{query} -> {response}")

    if MyArguments.netlayer:

        #DEBUG MODE
        #print(CaptureNetLayer(MyCapture))

        NLResults = CaptureNetLayer(MyCapture)

        print("Here are the results of the network layer")
        for flow, count in NLResults.items():
            print(f"{flow}: {count} paquets")





if __name__ == "__main__":
    main()