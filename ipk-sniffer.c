#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <getopt.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>

#define IPV4 0x0800
#define IPV6 0x86DD
#define ARP 0x0806

#define ICMP 0x01
#define ICMPV6 0x3A
#define TCP 0x06
#define UDP 0x11

pcap_t * interface_handle = NULL;

/**
 * Structure for the settings from program arguments.
 */
struct ProgramSettings {

    // filter flags
    int tcp;
    int udp;
    int arp;
    int icmp;

    char* port;
    char* interface;

    long num; // number of packets to display

};

/**
 * Exit program with specified exit value and message. This function unifies the format of the error message.
 * @param exit_val value to exit with
 * @param msg the error message specifying the reason of the error.
 */
void exit_with_error_msg(int exit_val, const char* msg) {
    fprintf(stderr, "[E]: %s\n", msg);
    exit(exit_val);
}

/**
 * Handles the ctrl+c interrupt.
 */
void signal_int_handler() {
    pcap_close(interface_handle);
    exit(EXIT_SUCCESS);
}

/**
 * Retrieves all available interfaces and prints them to STDOUT.
 * WARNING: the function terminates the program if any error occurs!
 */
void dump_active_interfaces_to_stdout() {
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs = NULL;

    // retrieve availible interfaces
    if ( pcap_findalldevs(&alldevs, error_buffer) == PCAP_ERROR ) {
        pcap_freealldevs(alldevs);
        exit_with_error_msg(EXIT_FAILURE, error_buffer);
    }

    // cycle through the list of interfaces and print them
    pcap_if_t *alldevs_tmp = alldevs;
    printf("Available interfaces:\n");
    if ( alldevs != NULL ) {
        printf("\t%s\n", alldevs->name);
        while (alldevs->next != NULL) {
            alldevs = alldevs->next;
            printf("\t%s\n", alldevs->name);
        }
    } else {
        printf("\tThere are no available interfaces!\n");
    }

    //free the list
    pcap_freealldevs(alldevs_tmp);
}

/**
 * Parsing of the program arguments. This function fills the ProgramSettings structure.
 * WARNING: the function terminates the program if any error occurs!
 * @param argc number of arguments passed to the program (same as argc from C main)
 * @param argv the arguments passed to the program (same as argv form C main)
 * @param settings the ProgramSettings structure
 */
void parse_arguments(int argc, char *argv[], struct ProgramSettings *settings) {

    // Define the long options.
    struct option long_options[] = {
            {"interface", optional_argument, NULL, 'i'},
            {"tcp", no_argument, NULL, 't'},
            {"udp", no_argument, NULL, 'u'},
            {"arp", no_argument, &(settings->arp), 1},
            {"icmp", no_argument, &(settings->icmp), 1},
            {0, 0, 0, 0}
    };


    int option;
    int longopt_index = 0;
    char *reminder;
    long num;
    int port;

    // No arguments cause the program to print active interfaces and exit.
    if ( argc == 1 ) {
        dump_active_interfaces_to_stdout();
        exit(EXIT_SUCCESS);
    }

    while ( (option = getopt_long(argc, argv, "tui::p:n:", long_options, &longopt_index)) != -1 ) {

        switch (option) {

            case 0: // one of the --arp or --icmp arguments

                if ( optarg != NULL ) {
                    exit_with_error_msg(EXIT_FAILURE, "Unexpected argument for --arp or --icmp option");
                }

                break;

            case 't': // the -t or --tcp argument
                if ( optarg != NULL ) {
                    exit_with_error_msg(EXIT_FAILURE, "Unexpected argument for -t or --tcp option");
                }
                settings->tcp = 1;
                break;

            case 'u': // the -u or --udp argument
                if ( optarg != NULL ) {
                    exit_with_error_msg(EXIT_FAILURE, "Unexpected argument for -u or --udp option");
                }
                settings->udp = 1;
                break;

            case 'i': // the -i or  --interface  argument

                // Since the documentation of getopt_long does not provide a suitable way
                // to set the separator of an argument (and it seems that the = is by default the only option)
                // we need to take a look at the next element in argv to decide if the it really is there
                if ( optarg == NULL && argv[optind] != NULL && argv[optind][0] != '-' ) {
                    optarg = argv[optind];
                    optind++;
                }

                if ( optarg == NULL ) {
                    // find the available interfaces and terminate the program
                    dump_active_interfaces_to_stdout();
                    exit(EXIT_SUCCESS);
                }
                settings->interface = optarg;
                break;

            case 'p': // the -p argument

                if ( optarg == NULL ) {
                    exit_with_error_msg(EXIT_FAILURE, "Argument of -p option missing!");
                }

                port = strtol(optarg, &reminder, 10);
                if ( *reminder != '\0' ) {
                    exit_with_error_msg(EXIT_FAILURE, "Argument of -p option is not a number!");
                }
                if ( port < 0 || port > 65535) {
                    exit_with_error_msg(EXIT_FAILURE, "Invalid port!");
                }
                settings->port = optarg;
                break;

            case 'n': // the -n argument
                num = strtol(optarg, &reminder, 10);
                if ( *reminder != '\0' ) {
                    exit_with_error_msg(EXIT_FAILURE, "Argument of -n option is not a number!");
                }
                if ( num <= 0 ) {
                    exit_with_error_msg(EXIT_FAILURE, "Invalid number of packets!");
                }
                settings->num = num;
                break;

            case '?':
                exit(EXIT_FAILURE);
        }
    }

    // if no flags were triggered set them all
    if ( settings->tcp == 0 && settings->arp == 0 && settings->udp == 0  && settings->icmp == 0 ) {
        settings->tcp = settings->arp = settings->udp = settings->icmp = 1;
    }
}

/**
 * Creates the filter out of ProgramSettings flags.
 * @param settings the ProgramSettings structure
 * @param buffer the buffer for the filter
 */
void create_filter_expr(struct ProgramSettings *settings, char *buffer) {

    if ( settings->tcp == 1 ) {
        strcat(buffer, "tcp");
        if ( settings->port != NULL ) {
            strcat(buffer, " port ");
            strcat(buffer, settings->port);
        }
        strcat(buffer," or ");
    }
    if ( settings->udp == 1 ) {
        strcat(buffer, "udp");
        if ( settings->port != NULL ) {
            strcat(buffer, " port ");
            strcat(buffer, settings->port);
        }
        strcat(buffer, " or ");
    }
    if ( settings->icmp == 1 ) {
        strcat(buffer, "( icmp or icmp6 ) or ");
    }
    if ( settings->arp == 1 ) {
        strcat(buffer, "arp or ");
    }

    // remove trailing or from the filter
    buffer[strlen(buffer)-4] = '\0';
}

/**
 * Prints the packets HEX and ASCII representation to the STDOUT.
 * @param packet pointing to the packet
 * @param caplen length of the packet
 */
void dump_packet_to_stdout(const u_char *packet, int caplen) {

    int cnt = 0; // the number of values in a row (max is 16)
    int i = 0; // the index in the packet

    printf("0x0000: "); // initial offset

    while ( i < caplen ) {

        // print a value to the a row
        printf("%02x ", packet[i]);
        i++;
        cnt++;

        // separate each set of 8 with double space
        if ( i % 8 == 0 ) {
            printf(" ");
        }

        // after each set of 16 print ASCII representation of the same 16 values
        if ( i % 16 == 0 ) {

            for ( int j = cnt; j > 0; j-- ) {
                if (isprint(packet[i-j])){
                    printf("%c", packet[i-j]);
                } else {
                    printf(".");

                }
            }

            cnt = 0;
            printf("\n");

            if ( i < caplen ) {
                printf("0x%04x: ", i);
            }
        }

    }

    // if there are no more values in the last line end
    if ( cnt == 0 ) {
        printf("\n");
        return;
    }

    // there are some values in last line so print spaces and ascii values for them
    int spaces = 16-cnt; // number of spaces until we can print the remaining ascii characters
    if ( cnt < 8 ) {
        printf("  ");
    } else {
        printf(" ");
    }
    for (;spaces>0;spaces--) {
        printf("   ");
    }

    // print the remaining ascii characters
    for ( int j = cnt; j > 0; j--) {
        if (isprint(packet[i-j])){
            printf("%c", packet[i-j]);
        } else {
            printf(".");
        }
    }
    printf("\n");

}

/**
 * Prints ip address to the STDOUT.
 * @param ip_addr ip address as integer
 */
void print_ip_address(u_int32_t ip_addr) {
    for ( int i = 3; i >= 0; i-- ) {
        printf("%d", ip_addr >> (i*8) & 0xFF);
        if (i!=0) {
            printf(".");
        }
    }
}

/**
 * Prints ipv6 address to the STDOUT.
 * @param address in6_addr structure representation of the address
 */
void print_ipv6_address(struct in6_addr *address) {
    char buffer[256] = "";
    inet_ntop(AF_INET6, address, buffer, 256);
    printf("%s", buffer);
}

/**
 * Prints mac address to the STDOUT.
 * @param address mac address integer representation
 */
void print_mac_address(u_int8_t *address) {
    for ( int i = 0; i < 6; i++) {
        printf("%02x", address[i]);
        if ( i != 5 ) {
            printf(":");
        }
    }
}

/**
 * Convert the timestamp from pcap library to the RFC3339 format
 * @param time_stamp
 */
void print_time_stamp(struct timeval time_stamp) {

    char time_stamp_buffer[256] = "";
    char gmt_sign;

    // get base form the provided value -> date and time
    struct tm* time_stamp_local = localtime(&time_stamp.tv_sec);
    strftime(time_stamp_buffer, 256, "%Y-%m-%dT%H:%M:%S", time_stamp_local);

    // GMT offset
    int gmtoff = time_stamp_local->tm_gmtoff;
    if ( time_stamp_local->tm_gmtoff >= 0 ) {
        gmt_sign = '+';
    }
    else {
        gmt_sign = '-';
    }

    // print the final format
    printf("%s.%03ld%c%02d:%02d", time_stamp_buffer, time_stamp.tv_usec/1000,gmt_sign,gmtoff/3600,gmtoff%3600);

}

/**
 * Callback function for the pcap_loop. Handles the recognition of the packets and the
 * displaying of the necessary information on the STDOUT.
 * @param user
 * @param hdr
 * @param packet
 */
void handle_packets(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet) {

    // Ethernet header
    struct ether_header* ethr = (struct ether_header*)packet;

    // extract the EthrType from Ethernet frame
    u_int16_t ethr_type =  ntohs(ethr->ether_type);

    if ( ethr_type == IPV4 ) {
        printf("-----------------------------------------------------------------\n");
        printf("ETHR TYPE: IPV4\n");

        const u_char *ipv4_packet = packet + 14;
        struct iphdr* ipv4_hdr = (struct iphdr*)(packet+14);

        // determine the header size
        int ipv4_header_size = ipv4_hdr->ihl * 4;
        const u_char *ipv4_payload = ipv4_packet + ipv4_header_size;

        // get protocol and ip adresses from the header
        u_int8_t ipv4_protocol = ipv4_hdr->protocol;
        u_int32_t ipv4_src_addr = ntohl(ipv4_hdr->saddr);
        u_int32_t ipv4_dst_addr = ntohl(ipv4_hdr->daddr);

        if ( ipv4_protocol == TCP) {

            // get the ports from the tcp header
            struct tcphdr *tcp_hdr = (struct tcphdr *) ipv4_payload;
            u_int16_t src_port = ntohs(tcp_hdr->th_sport);
            u_int16_t dst_port = ntohs(tcp_hdr->th_dport);

            //print the information
            printf("Protocol: TCP\n");
            print_time_stamp(hdr->ts);
            printf(" IP: ");
            print_ip_address(ipv4_src_addr);
            printf(" : %d", src_port);
            printf(" > IP: ");
            print_ip_address(ipv4_dst_addr);
            printf(" : %d", dst_port);
            printf(", length: %d", hdr->len);
            printf("\n");

        } else if ( ipv4_protocol == UDP) {

            // get the prots form the udp header
            struct udphdr *udp_hdr = (struct udphdr *) ipv4_payload;
            u_int16_t src_port = ntohs(udp_hdr->uh_sport);
            u_int16_t dst_port = ntohs(udp_hdr->uh_dport);

            // print the information
            printf("Protocol: UDP\n");
            print_time_stamp(hdr->ts);
            printf(" IP: ");
            print_ip_address(ipv4_src_addr);
            printf(" : %d", src_port);
            printf(" > IP: ");
            print_ip_address(ipv4_dst_addr);
            printf(" : %d", dst_port);
            printf(", length: %d", hdr->len);
            printf("\n");

        } else if ( ipv4_protocol == ICMP) {

            // print the information
            printf("Protocol: ICMP\n");
            print_time_stamp(hdr->ts);
            printf(" IP: ");
            print_ip_address(ipv4_src_addr);
            printf(" > IP: ");
            print_ip_address(ipv4_dst_addr);
            printf(", length: %d", hdr->len);
            printf("\n");

        } else {
            return;
        }
    }
    else if (  ethr_type == IPV6 ) {
        printf("-----------------------------------------------------------------\n");
        printf("ETHR TYPE: IPV6\n");

        // position of this header
        const u_char *ipv6_packet = packet+14;
        struct ip6_hdr *ipv6_hdr = (struct ip6_hdr*) ipv6_packet;
        const u_char *ipv6_payload = ipv6_packet+40;

        // get the protocol of child header
        u_int8_t ipv6_protocol = ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt;

        // get source and destination address
        struct in6_addr src_addr = ipv6_hdr->ip6_src;
        struct in6_addr dst_addr = ipv6_hdr->ip6_dst;

        if ( ipv6_protocol == TCP ) {

            // get the ports from the tcp header
            struct tcphdr *tcp_hdr = (struct tcphdr *) ipv6_payload;
            u_int16_t src_port = ntohs(tcp_hdr->th_sport);
            u_int16_t dst_port = ntohs(tcp_hdr->th_dport);

            // print the information
            printf("Protocol: TCP\n");
            print_time_stamp(hdr->ts);
            printf(" IP: ");
            print_ipv6_address(&src_addr);
            printf(" : %d", src_port);
            printf(" > IP: ");
            print_ipv6_address(&dst_addr);
            printf(" : %d", dst_port);
            printf(", length: %d", hdr->len);
            printf("\n");

        }
        else if ( ipv6_protocol == UDP ) {

            // get the ports form the udp header
            struct udphdr *udp_hdr = (struct udphdr *) ipv6_payload;
            u_int16_t src_port = ntohs(udp_hdr->uh_sport);
            u_int16_t dst_port = ntohs(udp_hdr->uh_dport);

            // print the information
            printf("Protocol: UDP\n");
            print_time_stamp(hdr->ts);
            printf(" IP: ");
            print_ipv6_address(&src_addr);
            printf(" : %d", src_port);
            printf(" > IP: ");
            print_ipv6_address(&dst_addr);
            printf(" : %d", dst_port);
            printf(", length: %d", hdr->len);
            printf("\n");

        }
        else if ( ipv6_protocol == ICMPV6 ) {

            // print the information
            printf("Protocol: ICMP\n");
            print_time_stamp(hdr->ts);
            printf(" IP: ");
            print_ipv6_address(&src_addr);
            printf(" > IP: ");
            print_ipv6_address(&dst_addr);
            printf(", length: %d", hdr->len);
            printf("\n");

        }
        else {
            return;
        }

    }
    else if (  ethr_type == ARP ) {

        printf("-----------------------------------------------------------------\n");
        printf("ETHR TYPE: ARP\n");

        // get the source and destination addresses from the ethernet frame header
        u_int8_t *dst_addr = ethr->ether_dhost;
        u_int8_t *src_addr = ethr->ether_shost;

        // print the info info form packet
        print_time_stamp(hdr->ts);
        printf(" IP: ");
        print_mac_address(src_addr);
        printf(" > IP: ");
        print_mac_address(dst_addr);
        printf(", length: %d", hdr->len);
        printf("\n");

    } else {
        return;
    }

    dump_packet_to_stdout(packet, hdr->caplen);
}

int main(int argc, char *argv[]) {

    signal(SIGINT, signal_int_handler);

    struct ProgramSettings settings ;
    char errbuf[PCAP_ERRBUF_SIZE] = "";

    settings = (struct ProgramSettings){0,0,0,0,NULL,NULL,1};

    parse_arguments(argc, argv, &settings);

    //printf("Settings:\n\ttcp: %d\n\tarp: %d\n\tudp: %d\n\ticmp: %d\n\tport: %s\n\tinterface: %s\n\tnum: %ld\n",
    //       settings.tcp, settings.arp, settings.udp, settings.icmp, settings.port, settings.interface, settings.num);

    // handle creation
    interface_handle = pcap_create(settings.interface, errbuf);
    if ( interface_handle == NULL ) {
        pcap_close(interface_handle);
        interface_handle = NULL;
        exit_with_error_msg(EXIT_FAILURE, errbuf);
    }

    // set immediate mode - packets will be handled at the same time they are received
    if ( pcap_set_immediate_mode(interface_handle,100) != 0 ) {
        pcap_close(interface_handle);
        interface_handle = NULL;
        exit_with_error_msg(EXIT_FAILURE, "Immediate mode wasn't set successfuly!");
    }

    // handle activation
    int ret = pcap_activate(interface_handle);
    if ( ret != 0 ) {
        pcap_close(interface_handle);
        interface_handle = NULL;
        exit_with_error_msg(EXIT_FAILURE, pcap_statustostr(ret));
    }

    // setting the data link
    if (pcap_datalink(interface_handle) != DLT_EN10MB) {
        pcap_close(interface_handle);
        interface_handle = NULL;
        exit_with_error_msg(EXIT_FAILURE, "Specified interface doesn't provide Ethernet headers!");
	}
    pcap_set_datalink(interface_handle, DLT_EN10MB);

    // setting packet filter
    char filter[256] = "";
    create_filter_expr(&settings, filter);
    struct bpf_program bpf;
    uint32_t  src_ip, netmask;

    // get netmask in order to set packet filter
    if ( pcap_lookupnet(settings.interface, &src_ip, &netmask, errbuf) < 0 ) {
        pcap_close(interface_handle);
        interface_handle = NULL;
        exit_with_error_msg(EXIT_FAILURE, errbuf);
    }

    // compilation of filter expression
    if ( pcap_compile(interface_handle, &bpf, filter, 0, netmask) == PCAP_ERROR ) {
        pcap_perror(interface_handle, "[E]: pcap_compile");
        pcap_close(interface_handle);
        interface_handle = NULL;
        exit(EXIT_FAILURE);
    }

    // set the compiled filter
    if ( pcap_setfilter(interface_handle, &bpf) < 0 ) {
        pcap_perror(interface_handle, "[E]: pcap_setfilter");
        pcap_freecode(&bpf);
        pcap_close(interface_handle);
        interface_handle = NULL;
        exit(EXIT_FAILURE);
    }
    pcap_freecode(&bpf);

    // packets sniffing
    if ( pcap_loop(interface_handle, settings.num, handle_packets, NULL) != 0 ) {
        pcap_perror(interface_handle, "[E]: pcap_loop");
        pcap_close(interface_handle);
        interface_handle = NULL;
        exit(EXIT_FAILURE);
    }
    pcap_close(interface_handle);
    interface_handle = NULL;
    return 0;
}
