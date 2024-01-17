#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#define MAX_CONNECTIONS 1000

struct Connection {
    uint32_t src_ip;
    uint32_t dst_ip;
};

struct Connection connections[MAX_CONNECTIONS];
int connection_count = 0;
static pcap_dumper_t *pcap_dumper = NULL;
static pcap_t *handle = NULL;

uint32_t filter_ip; // Single IP filter

int is_new_connection(uint32_t src_ip, uint32_t dst_ip) {
    for (int i = 0; i < connection_count; ++i) {
        if ((connections[i].src_ip == src_ip && connections[i].dst_ip == dst_ip) ||
            (connections[i].dst_ip == src_ip && connections[i].src_ip == dst_ip)) {
            return 0; // Connection already seen
        }
    }
    return 1; // New connection
}

void add_connection(uint32_t src_ip, uint32_t dst_ip) {
    if (connection_count < MAX_CONNECTIONS) {
        connections[connection_count].src_ip = src_ip;
        connections[connection_count].dst_ip = dst_ip;
        connection_count++;
    }
}

void packet_handler(const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    uint32_t src_ip = *(uint32_t*)(packet + 26);
    uint32_t dst_ip = *(uint32_t*)(packet + 30);

    if (src_ip == filter_ip || dst_ip == filter_ip) {
        if (is_new_connection(src_ip, dst_ip)) {
            add_connection(src_ip, dst_ip);
        }
        pcap_dump((unsigned char *)pcap_dumper, pkthdr, packet);
    }
}

int main(int argc, char *argv[]) {
    time_t start_time = time(NULL);
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = "eth0"; // Replace with your actual network device
    char filename[100];

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <IP>\n", argv[0]);
        return 1;
    }

    filter_ip = inet_addr(argv[1]);

    // Check if the tracking directory exists, if not, create it
    struct stat st = {0};
    if (stat("tracking", &st) == -1) {
        mkdir("tracking", 0777); // Note the permission settings
    }
    // Construct the filename using the IP
    sprintf(filename, "tracking/%s.pcap", argv[1]);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", dev, errbuf);
        return 2;
    }

    pcap_dumper = pcap_dump_open(handle, filename);
    if (pcap_dumper == NULL) {
        fprintf(stderr, "Could not open output file %s: %s\n", filename, pcap_geterr(handle));
        pcap_close(handle);
        return 2;
    }

    struct pcap_pkthdr *header;
    const unsigned char *packet;
    int res;
    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0) {
            continue; // Timeout elapsed
        }

        // Check for 5 minutes elapsed (changed to 30 seconds here for testing)
        if (difftime(time(NULL), start_time) >= 30) { // 300 seconds = 5 minutes
            break;
        }

        packet_handler(header, packet);
    }
    pcap_dump_close(pcap_dumper);
    pcap_close(handle);

    return 0;
}
