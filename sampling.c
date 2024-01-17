#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MAX_CONNECTIONS 1000
static int packets_per_file;  // Global variable declaration

struct Connection {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    int packet_count;
};

struct Connection connections[MAX_CONNECTIONS];
int connection_count = 0;
static pcap_dumper_t *pcap_dumper = NULL;
static pcap_t *handle = NULL;
static int packets_per_file = 100; // Default value
static int packets_per_connection = 5; // Default value
static int packets_written = 0;


void get_new_filename(char *filename, size_t filename_size, const char *date_folder) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char temp_path[256];
    // Format the date into the date_folder string
    strftime(date_folder, filename_size, "sampling/sampling/%y_%m_%d_%H_%M_%S", tm_info);

    strftime(filename, filename_size, "sampling/%y_%m_%d_%H_%M_%S/output_%Y%m%d%H%M%S.pcap", tm_info);
}



void rotate_file_if_needed() {
    if (packets_written >= packets_per_file) {  // Use the variable instead of the macro
        char filename[64];
        char date_folder[64]; // Additional buffer for the date-specific folder

        // Close current file and open a new one
        pcap_dump_close(pcap_dumper);

        // Call get_new_filename with the correct number of arguments
        get_new_filename(filename, sizeof(filename), date_folder);
        
        pcap_dumper = pcap_dump_open(handle, filename);
        if (pcap_dumper == NULL) {
            fprintf(stderr, "rotate - Could not open output file %s\n", filename);
            exit(1);
        }

        // Reset packets written counter
        packets_written = 0;
    }
}

int is_new_connection(const struct Connection* conn, int* index) {
    for (int i = 0; i < connection_count; ++i) {
        if (connections[i].src_ip == conn->src_ip &&
            connections[i].dst_ip == conn->dst_ip &&
            connections[i].src_port == conn->src_port &&
            connections[i].dst_port == conn->dst_port) {
            *index = i; // Pass back the index of the existing connection
            return 0; // Connection already seen
        }
    }
    return 1; // New connection
}

void add_connection(const struct Connection* conn) {
    if (connection_count < MAX_CONNECTIONS) {
        connections[connection_count] = *conn;
        connections[connection_count].packet_count = 0; // Initialize packet count
        connection_count++;
    }
}

void packet_handler(const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct Connection conn;

    // Extract source and destination IP addresses and ports
    conn.src_ip = *(uint32_t*)(packet + 26);
    conn.dst_ip = *(uint32_t*)(packet + 30);
    conn.src_port = *(uint16_t*)(packet + 34);
    conn.dst_port = *(uint16_t*)(packet + 36);

    int index;
    if (is_new_connection(&conn, &index)) {
        add_connection(&conn);
        index = connection_count - 1; // Index of the newly added connection
    }

    // Capture only the first 'packets_per_connection' packets per connection
    if (connections[index].packet_count < packets_per_connection) {
        connections[index].packet_count++;
        
        // Write the packet to the pcap file
        if (pcap_dumper != NULL) {
            pcap_dump((unsigned char *)pcap_dumper, pkthdr, packet);
            packets_written++;
        }

        // Check if file rotation is needed
        rotate_file_if_needed();
    }
}


int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    char filename[64];
    char date_folder[64];
    //char *dev = "\\Device\\NPF_{DAAEA3FD-18FB-4617-AE2C-DB88D2548DE7}";
    char *dev = "eth0";
    if (argc != 4) {
    fprintf(stderr, "Usage: %s <PacketsPerFile> <PacketsPerConnection> <DurationInSeconds>\n", argv[0]);
    struct stat st = {0};
    return 1;
}

packets_per_file = atoi(argv[1]);  // Parse the value from arguments
packets_per_connection = atoi(argv[2]);
int duration_in_seconds = atoi(argv[3]);

if (packets_per_file <= 0 || packets_per_connection <= 0 || duration_in_seconds <= 0) {
    fprintf(stderr, "Error: Arguments must be positive integers.\n");
    return 1;
}

handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
if (handle == NULL) {
    fprintf(stderr, "Could not open device %s: %s\n", dev, errbuf);
    return 2;
}

// Prepare the output file name and create directories if necessary
get_new_filename(filename, sizeof(filename), date_folder);

if (mkdir("sampling", 0755) == -1) {
    printf("error creating sampling");
}

char dirname[64];
time_t now = time(NULL);
struct tm *tm_info = localtime(&now);
char temp_path[256];

    // Updated format: year_month_day_hour_minute_second
strftime(dirname, sizeof(dirname), "sampling/%y_%m_%d_%H_%M_%S", tm_info);

if (mkdir(dirname, 0755) == -1) {
    perror("Error creating directory");
}


pcap_dumper = pcap_dump_open(handle, filename);
if (pcap_dumper == NULL) {
    fprintf(stderr, "first - Could not open output file %s: %s\n", filename, pcap_geterr(handle));
    pcap_close(handle);
    return 2;
}

time_t start_time = time(NULL);
struct pcap_pkthdr *header;
const unsigned char *packet;
int res;

// Begin packet capture loop
while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
    // Check if the capture duration has elapsed
    if (difftime(time(NULL), start_time) > duration_in_seconds) {
        break; // Stop capturing after the specified duration
    }

    if (res == 0) {
        // Timeout elapsed
        continue;
    }
    
    packet_handler(header, packet);
    rotate_file_if_needed();
}

// Cleanup before finishing
pcap_dump_close(pcap_dumper);
pcap_close(handle);

return 0;
}
