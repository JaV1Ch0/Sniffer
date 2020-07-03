import socket
import sys
import struct

TAB_1 = '    '

print("NOMBRE:")
print("JAVIER PEÑA LEYTON")
print("PARALELO:")
print("B (Lic. Gallardo Martes)")

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        packet= s.recvfrom(65536)
        packet = packet[0]

        ip_header = packet[0:20]

        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

        print('\n##############################################################')
        print("\n")
        version_ihl = iph[0]
        version = version_ihl >> 4

        ihl = version_ihl & 0xF
        iph_length = ihl * 4

        ip_tos = iph[1] 
        ip_len = iph[2]  
        ip_id = iph[3] 
        ip_off = iph[4]
        ip_off_1 = bin(iph[4])[2:].zfill(16)  
        ip_rb = ip_off_1[0:1]
        ip_df = ip_off_1[1:2]
        ip_mf = ip_off_1[2:3]
        ip_ttl = iph[5] 
        ip_p = iph[6]
        ip_sum = iph[7]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        tcp_header = packet[iph_length:iph_length+20]

        tcph = struct.unpack('!HHLLBBHHH', tcp_header)

        source_port = tcph[0] 
        dest_port = tcph[1]  
        sequence = tcph[2]    
        acknowledgement = tcph[3]  
        doff_reserved = tcph[4]     
        tcph_length = doff_reserved >> 4
        tcph_flags = tcph[5]  
        tcph_flags_1 = bin(tcph[5])[2:].zfill(16)
        fla_URG = tcph_flags_1[10:11]
        fla_ACK = tcph_flags_1[11:12]
        fla_PSH = tcph_flags_1[12:13]
        fla_RST = tcph_flags_1[13:14]
        fla_SYN = tcph_flags_1[14:15]
        fla_FIN = tcph_flags_1[15:16]
        tcph_window_size = tcph[6]
        tcph_checksum = tcph[7] 
        tcph_checksum_1 = tcph_checksum
        tcph_urgent_pointer = tcph[8] 

        icmp_type, icmp_code, icmp_checksum = struct.unpack('! B B H', packet[:4])

        udp_src_port, udp_dest_port, udp_size = struct.unpack('! H H 2x H', packet[:8])
                
        dest_mac, src_mac, eth_proto, data = ethernet_frame(packet)

        print('\nEthernet Header: ')
        print(TAB_1 + '|-Destination Address : {}'.format(dest_mac))
        print(TAB_1 + '|-Source Address      : {}'.format(src_mac))
        print(TAB_1 + '|-Protocol            : {}'.format(eth_proto))
        print("")
        
        print("\nIP Header")
        print(TAB_1 + '|-IP Version         : {}'.format(str(version)))
        print(TAB_1 + '|-IP Header Length   : {}'.format(ihl), 'DWORDS or', str(ihl*32//8), 'bytes')
        print(TAB_1 + '|-Type of Service    : {}'.format(str(ip_tos)))
        print(TAB_1 + '|-IP Total Length    : {}'.format(ip_len),
              ' DWORDS ', str(ip_len*32//8), 'bytes')
        print(TAB_1 + '|-Identification     : {}'.format(ip_id))
        print(TAB_1 + '|-Flag: ', ip_off)
        print(TAB_1 + '|-R Reserved Flag    : {}'.format(ip_rb))
        print(TAB_1 + '|-DF Dont Fragment Flag : {}'.format(ip_df))
        print(TAB_1 + '|-MF More Fragment Flag : {}'.format(ip_mf))
        print(TAB_1 + '|-TTL                : {}'.format(str(ip_ttl)))
        print(TAB_1 + '|-Protocol           : {}'.format(ip_p))
        print(TAB_1 + '|-Chksum             : {}'.format(ip_sum))
        print(TAB_1 + '|-Source Address IP  : {}'.format(str(s_addr)))
        print(TAB_1 + '|-Destination Address IP : {}'.format(str(d_addr)))
        

        if ip_p == 1:
            print('\nICMP Header')
            print(TAB_1 + '|-Type        : {}'.format(icmp_type))
            print(TAB_1 + '|-Code        : {}'.format(icmp_code))
            print(TAB_1 + '|-hecksum     : {}'.format(icmp_checksum))
            print(TAB_1 + '|-ICMP Data   :')
            print(TAB_1 + '|-Data        : {}'.format(data))
            

        if ip_p == 6:
            print("\nTCP Header")
            print(TAB_1 + "|-Source Port          : {}".format(source_port))
            print(TAB_1 + "|-Destination Port     : {}".format(dest_port))
            print(TAB_1 + "|-Sequence Number      : {}".format(sequence))
            print(TAB_1 + "|-Acknowledge Number   : {}".format(acknowledgement))
            print(TAB_1 + "|-Header Length        : {}".format(tcph_length),
                'DWORDS or ', str(tcph_length*32//8), 'bytes')
            print(TAB_1 + "|-Flag                 : {}".format(tcph_flags))
            print(TAB_1 + '|-Urgent Flag          : {}'.format(fla_URG))
            print(TAB_1 + '|-Acknowlegement Flag  : {}'.format(fla_ACK))
            print(TAB_1 + '|-Push Flag            : {}'.format(fla_PSH))
            print(TAB_1 + '|-Reset Flag           : {}'.format(fla_RST))
            print(TAB_1 + '|-Synchronise Flag     : {}'.format(fla_SYN))
            print(TAB_1 + '|-Finish Flag          : {}'.format(fla_FIN))
            print(TAB_1 + "|-Window Size          : {}".format(tcph_window_size))
            print(TAB_1 + "|-Checksum             : {}".format(tcph_checksum))
            print(TAB_1 + "|-Urgent Pointer       : {}".format(tcph_urgent_pointer))
            h_size = iph_length + tcph_length * 4
            data_size = len(packet) - h_size
            data = packet[h_size:]
            print(TAB_1 + '|-Data : {}'.format(str(data)))
            

        if ip_p == 17:
            print('\nUDP Segment:')
            print(TAB_1 + '|-Source Port       : {}'.format(udp_src_port))
            print(TAB_1 + '|-Destination Port  : {}'.format(udp_dest_port))
            print(TAB_1 + '|-Length            : {}'.format(udp_size))
            print(TAB_1 + '|-Data              : {}'.format(data))
            
        
        if ip_p != 1 and ip_p != 6 and ip_p != 17:
            print("Otro Protocolo.")

def ipv4(addr):
    return '.'.join(map(str, addr))
    
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

main()
