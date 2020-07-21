#include <string>
#include <cstring>
#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

using namespace std;

void show_interface();
void traffic(const char *interface);
void pcap_f(const char *file);
void analysis(pcap_t * pcap);
void usage();

int main(int argc, char *argv[])
{
    switch (argc) {
    case 3:
        if (strcmp(argv[1], "-t") == 0) {
            const char *interface = argv[2];
            traffic(interface);
        } else if (strcmp(argv[1], "-f") == 0) {
            const char *file = argv[2];
            pcap_f(file);
        } else {
            usage();
        }
        break;
    default:
        usage();
        return -1;
    }
}

void show_interface() {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Show Interface
    pcap_if_t *alldevs;
    pcap_if_t *d;

    if (pcap_findalldevs(&alldevs, errbuf) < 0) {
        printf("pcap_findalldevs error\n");
    }

    printf("Interface:\n");
    for (d=alldevs; d; d=d->next) {
        printf("\t%s\n", (d->description)?(d->description):(d->name));
    }
    printf("\n");
}

void traffic(const char *interface) {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *traffic = pcap_open_live(interface, 65536, 1, 1000, errbuf);
    if (traffic == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", interface, errbuf);
        exit(-1);
    }

    analysis(traffic);
}

void pcap_f(const char *file) {
    // Create an char array to hold the error.
    char errbuf[PCAP_ERRBUF_SIZE];
 
    // Step 4 - Open the file and store result in pointer to pcap_t
    pcap_t * pcap = pcap_open_offline(file, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "pcap_open_offline(%s) return nullptr - %s\n", file, errbuf);
        exit(-1);
    }

    analysis(pcap);
}

void analysis(pcap_t * pcap) {
    // Step 5 - Create a header and a data object
    struct pcap_pkthdr *header;
    struct ether_header *eth_header;
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    u_char *tcp_payload;
    u_char *payload;

    const u_char *data;
    int payload_size;
 
    // Step 6 - Loop through packets and print them to screen
    u_int packetCount = 0;
    while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0)
    {
        if (returnValue == 0) continue;
        if (returnValue == -1 || returnValue == -2) {
            printf("pcap_next_ex return %d(%s)\n", returnValue, pcap_geterr(pcap));
            break;
        }

        // Show the packet TCP info
        eth_header = (struct ether_header *)(data);
        ip_header = (struct ip *)(data + sizeof(struct ether_header));
        tcp_header = (struct tcphdr *)(data + sizeof(struct ether_header) \
         + sizeof(struct ip));
        tcp_payload = (u_char *)(data + \
        sizeof(struct ether_header) + sizeof(struct ip));
        payload = (u_char *)(data + \
        sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));

        u_int8_t *dmac = eth_header->ether_dhost;
        u_int8_t *smac = eth_header->ether_shost;
        u_int16_t type = ntohs(eth_header->ether_type);

        payload_size = strlen((char*)payload);

        printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x (0x%04x)\n",
            smac[0], smac[1], smac[2], smac[3], smac[4], smac[5], type);
        printf("Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5]);
        printf("Src: %s:%d\n", inet_ntoa(ip_header->ip_src), ntohs(tcp_header->th_sport));
        printf("Dest: %s:%d\n", inet_ntoa(ip_header->ip_dst), ntohs(tcp_header->th_dport));

        // Show the packet number
        printf("Packet # %i\n", ++packetCount);
 
        // Show the size in bytes of the packet
        printf("Packet size: %d bytes\n", header->len);
 
        // Show a warning if the length captured is different
        if (header->len != header->caplen)
            printf("Warning! Capture size different than packet size: %ld bytes\n", header->len);
 
        // Show Epoch Time
        printf("Epoch Time: %d:%d seconds\n", header->ts.tv_sec, header->ts.tv_usec);

        // loop through the packet and print it as hexidecimal representations of octets
        // We also have a function that does this similarly below: PrintData()
        printf("<TCP Payload>");
        //for (u_int i=0; i<sizeof(struct tcphdr); i++)
        for (u_int i=0; i<16; i++)
        {
            // Start printing on the next after every 16 octets
            if ( (i % 16) == 0) {
                printf("\n0x%04x ", i);
            }
            // Print each octet as hex (x), make sure there is always two characters (.2).
            printf("%02x ", tcp_payload[i]);
        }
        
        if (!payload_size == 0) {
            printf("\n<Payload>\n");
            printf("%s", payload);
        }
    
        // Add two lines between packets
        printf("\n\n");

        // Payload Memory initialization
        memset(payload, '\0', strlen((char*)payload));
    }
}

void usage(){
    show_interface();
    printf("syntax: libpcap -t <interface>\n");
    printf("syntax: libpcap -f <pcap file>\n");
}