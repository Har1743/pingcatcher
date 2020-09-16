import socket
import sys
from argparse import ArgumentParser
from struct import unpack

parser = ArgumentParser(description="A Command Line based tool which help to detect ping request and reply")
parser.add_argument("--analyse", "-a", help="Analysing mode [ This will analyse the "
                                            "ethernet-frame and then capture the the icmp packets"
                                            " ]", action="store_true", default=False)
argument = parser.parse_args()


# this will return proper format of mac address
def get_mac_address(mac):

    mac = map("{:02x}".format, mac)
    return ":".join(mac).upper()


# this will return proper format of ip address
def get_ip_address(ip):
    return ".".join(map(str, ip))


# this will unpack data from ethernet frame
def ethernet_frame(eth_data):

    dst_mac, src_mac, prototype = unpack("! 6s 6s H", eth_data[:14])
    dst_mac_address = get_mac_address(dst_mac)
    src_mac_address = get_mac_address(src_mac)
    prototype = socket.htons(prototype)

    return dst_mac_address, src_mac_address, prototype


# getting ipv4_packet info
def ipv4_packet(ipv4_data):

    version_header_length = ipv4_data[0]
    header_length = (version_header_length & 15) * 4
    ttl, packet_protocol, src_ipv4, dst_ipv4 = unpack("! 8x B B 2x 4s 4s", ipv4_data[:20])

    src_ipv4 = get_ip_address(src_ipv4)
    dst_ipv4 = get_ip_address(dst_ipv4)

    return version_header_length, header_length, ttl, packet_protocol, src_ipv4, dst_ipv4


# getting ipv6_packet info
def ipv6_packet(ipv6_data):

    version_class_flow_label, payload_len, next_header, hop_limit, src_ipv6, dst_ipv6 = unpack(
        "! 4s H B B 16s 16s", ipv6_data[:40])

    src_ipv6 = get_ip_address(src_ipv6)
    dst_ipv6 = get_ip_address(dst_ipv6)

    return version_class_flow_label, payload_len, next_header, hop_limit, src_ipv6, dst_ipv6


def ethernet_frame_info(eth):

    print("\033[1;31m++++++++++++++++++++++++++++++++++++++++++\033[1;m")
    print("Ethernet Frame Detected")
    print("Destination mac address {}".format(eth[0]))
    print("source mac address {}".format(eth[1]))
    print("Ethernet protocol {}".format(eth[2]))


def ipv4_packet_info(ipv4_info):

    print("\033[1;35m*******************************************\033[1;m")
    print("\t" "IPV4 Packet Detected")
    print("\t" + "Header Length {}".format(ipv4_info[1]))
    print("\t" + "Time To Live {}".format(ipv4_info[2]))
    print("\t" + "Packet protocol {}".format(ipv4_info[3]))
    print("\t" + "Source IP address {}".format(ipv4_info[4]))
    print("\t" + "Destination IP address {}".format(ipv4_info[5]))
    print("\033[1;35m*******************************************\033[1;m")
    print("\n")


def ipv6_packet_info(ipv6_info):

    print("\033[1;35m*******************************************\033[1;m")
    print("\t" "IPV4 Packet Detected")
    print("\t" + "Payload Length {}".format(ipv6_info[1]))
    print("\t" + "Next Header {}".format(ipv6_info[2]))
    print("\t" + "Hop Limit {}".format(ipv6_info[3]))
    print("\t" + "Source IP address {}".format(ipv6_info[4]))
    print("\t" + "Destination IP address {}".format(ipv6_info[5]))
    print("\033[1;35m*******************************************\033[1;m")
    print("\n")


def main():

    ping_encounter = 0
    print("\n")

    try:
        # creating socket
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except socket.error:
        print("\n" + "Error in socket creation")
        sys.exit(0)

    while True:
        try:
            # receiving data
            raw_data, address = s.recvfrom(2048)

            eth = ethernet_frame(raw_data)

            # checking it is an ipv4 packet
            if eth[2] == 8:
                ipv4_data = raw_data[14:]
                ipv4_info = ipv4_packet(ipv4_data)

                # check if it's icmp_v4 packet
                if ipv4_info[3] == 1:

                    # check if it's an ICMP_V4 packet ping request
                    if ipv4_data[ipv4_info[1]] == 8:
                        print("ping \033[93m[request]\033[00m from \033[93m{}\033[00m".format(ipv4_info[4]))

                    # check if it's an ICMP_V4 packet ping reply
                    elif ipv4_data[ipv4_info[1]] == 0:
                        print("ping \033[95m[reply]\033[00m from \033[95m{}\033[00m".format(ipv4_info[4]))

                    if argument.analyse:
                        ethernet_frame_info(eth)
                        ipv4_packet_info(ipv4_info)

                    ping_encounter = ping_encounter + 1

            elif eth[2] == 56710:
                ipv6_data = raw_data[14:]
                ipv6_info = ipv6_packet(ipv6_data)

                # check if it's icmp_v6 packet
                if ipv6_info[2] == 58:

                    # check if it's an ICMP_V6 packet ping request
                    if ipv6_data[ipv6_info[1]] == 8:
                        print("ping \033[93m[request]\033[00m from \033[93m{}\033[00m".format(ipv6_info[4]))

                    # check if it's an ICMP_V6 packet ping reply
                    elif ipv6_data[ipv6_info[1]] == 0:
                        print("ping \033[95m[reply]\033[00m from \033[95m{}\033[00m".format(ipv6_info[4]))

                    if argument.analyse:
                        ethernet_frame_info(eth)
                        ipv6_packet_info(ipv6_info)

                    ping_encounter = ping_encounter + 1

        # handling keyboard interruptions
        except KeyboardInterrupt:
            print("\n" + "keyboard interrupt")
            print("Total {} ping encountered".format(ping_encounter))
            sys.exit(0)


if __name__ == '__main__':
    main()
