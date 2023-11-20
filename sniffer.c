//
// Created by godzilla ( Artem Fedorchenko ) on 14/11/23.
//

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include <unistd.h>

#define MAX_BUFFER_SIZE 65536

void process_packet(unsigned char*, int);
void print_ip_header(unsigned char*, int size);
void print_tcp_header(unsigned char*, int);
void print_udp_header(unsigned char*, int);
void print_icmp_header(unsigned char*, int);
void print_data_into_file(unsigned char*, int);

int socket_raw;
FILE *log_file;
int tcp=0, udp=0, icmp=0,igmp=0,others=0,total=0,i,j;
struct sockaddr_in source,dest;

int main(){
    unsigned char *buffer = (unsigned char*) malloc(MAX_BUFFER_SIZE);
    int saddr_size , data_size;
    struct sockaddr saddr;
    struct in_addr in;
    log_file = fopen("/home/godzilla/CLionProjects/untitled/text_file.txt", "w");
    if (log_file == NULL){
        printf("Error creating a file\n");
        exit(STDERR_FILENO);
    }

    printf("Starting...");
    socket_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if (socket_raw < 0){
        printf("Error opening socket\n");
        exit(STDERR_FILENO);
    }

    while (1){
        saddr_size = sizeof saddr;
        data_size = recvfrom(socket_raw, buffer, MAX_BUFFER_SIZE, 0, &saddr, &saddr_size);

        if (data_size < 0){
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        process_packet(buffer, data_size);
    }
    close(socket_raw);
    printf("Socket closed");
    return 0;
}

void process_packet(unsigned char* buffer, int size){
    // create ip header struct
    struct iphdr* ip_header = (struct iphdr*) buffer;
    ++total;

    // switch according to protocol in the packet
    switch (ip_header->protocol) {
        case 1:
            ++icmp;
            print_icmp_header(buffer, size);
            break;
        case 2:
            ++igmp;
            break;
        case 6:
            ++tcp;
            print_tcp_header(buffer, size);
            break;
        case 17:
            ++udp;
            print_udp_header(buffer, size);
            break;
        default:
            ++total;
    }
    fprintf(log_file, "TOTAL: %d\nTCP: %d\nUDP: %d\nICMP: %d\nIGMP: %d", total, tcp, udp, icmp, igmp);
}

void print_ip_header(unsigned char* buffer, int size){
    struct iphdr* ip_header = (struct iphdr*) buffer;
    unsigned short ip_header_length = ip_header->ihl*4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip_header->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip_header->daddr;

    fprintf(log_file, "\n");
    fprintf(log_file, "@@@@@@@@ IP HEADER @@@@@@@@\n");
    fprintf(log_file, "|------- IP VERSION -> %d\n", ip_header->version);
    fprintf(log_file, "|------- IP HEADER LENGTH -> %d\n", ip_header_length);
    fprintf(log_file, "|------- TYPE OF SERVICE -> %d\n", ip_header->tos);
    fprintf(log_file, "|------- TOTAL LENGTH -> %d\n", ip_header->tot_len);
    fprintf(log_file, "|------- ID -> %d\n", ip_header->id);
    fprintf(log_file, "|------- TTL -> %d\n", ip_header->ttl);
    fprintf(log_file, "|------- PROTOCOL -> %d\n", ip_header->protocol);
    fprintf(log_file, "|------- CHECKSUM -> %d\n", ip_header->check);
    fprintf(log_file, "|------- SOURCE ADDR -> %s\n", inet_ntoa(source.sin_addr));
    fprintf(log_file, "|------- DESTINATION ADDR -> %s\n", inet_ntoa(dest.sin_addr));

}

void print_tcp_header(unsigned char* buffer, int size){
    struct iphdr* ip_header = (struct iphdr*) buffer;
    unsigned short ip_header_length = ip_header->ihl*4;

    struct tcphdr* tcp_header = (struct tcphdr*) (buffer+ip_header_length);
    print_ip_header(buffer, size);

    fprintf(log_file, "\n");
    fprintf(log_file, "@@@@@@@@ TCP HEADER @@@@@@@@\n");
    fprintf(log_file, "|------- SOURCE PORT -> %d\n", tcp_header->source);
    fprintf(log_file, "|------- DESTINATION PORT -> %d\n", tcp_header->dest);
    fprintf(log_file, "|------- SEQUENCE NUMBER -> %d\n", tcp_header->seq);
    fprintf(log_file, "|------- ACKNOWLEDGE NUMBER -> %d\n", tcp_header->ack_seq);
    fprintf(log_file, "|------- HEADER LENGTH -> %d\n", tcp_header->doff);
    fprintf(log_file, "|------- URGENT FLAG -> %d\n", tcp_header->urg);
    fprintf(log_file, "|------- ACKNOWLEDGEMENT FLAG -> %d\n", tcp_header->ack);
    fprintf(log_file, "|------- PUSH FLAG -> %d\n",tcp_header->psh);
    fprintf(log_file, "|------- RESET FLAGS -> %d\n", tcp_header->rst);
    fprintf(log_file, "|------- SYNCHRONIZE FLAGS -> %d\n", tcp_header->syn);
    fprintf(log_file, "|------- FINISH FLAG -> %d\n", tcp_header->fin);
    fprintf(log_file, "|------- WINDOW -> %d\n", tcp_header->window);
    fprintf(log_file, "|------- CHECKSUM -> %d\n", tcp_header->check);
    fprintf(log_file, "|------- URGENT POINTER -> %d\n", tcp_header->urg_ptr);
    fprintf(log_file, "\n");
    fprintf(log_file,"          RAW DATA         \n");
    print_data_into_file(buffer, ip_header_length);
    fprintf(log_file,"          TCP HEADER         \n");
    print_data_into_file(buffer+ip_header_length, tcp_header->doff*4);
    fprintf(log_file,"          DATA PAYLOAD         \n");
    print_data_into_file(buffer+ip_header_length+tcp_header->doff*4, (size - tcp_header->doff*4-ip_header->ihl*4));
    fprintf(log_file, "@@@@@@@@ TCP HEADER END @@@@@@@@\n");

}
void print_udp_header(unsigned char* buffer, int size){
    struct iphdr* ip_header = (struct iphdr*) buffer;
    unsigned short ip_header_len = ip_header->ihl*4;

    struct udphdr* udp_header = (struct udphdr*) (buffer+ip_header_len);
    fprintf(log_file, "\n");
    fprintf(log_file, "@@@@@@@@ UDP HEADER @@@@@@@@\n");
    print_ip_header(buffer, size);
    fprintf(log_file, "|------- SOURCE PORT -> %d\n", udp_header->source);
    fprintf(log_file, "|------- DESTINATION PORT -> %d\n", udp_header->dest);
    fprintf(log_file, "|------- UDP Length -> %d\n", udp_header->len);
    fprintf(log_file, "|------- CHECKSUM -> %d\n", udp_header->check);

    fprintf(log_file, "\n");
    fprintf(log_file, "IP HEADER");
    fprintf(log_file,"UDP Header\n");
    print_data_into_file(buffer+ip_header_len , sizeof(udp_header));

    fprintf(log_file,"Data Payload\n");
    print_data_into_file(buffer + ip_header_len + sizeof udp_header ,( size - sizeof udp_header - ip_header->ihl * 4 ));

}

void print_icmp_header(unsigned char* buffer, int size){
    struct iphdr* ip_header = (struct iphdr*) buffer;
    unsigned short ip_header_length = ip_header->ihl*4;

    struct icmphdr* icmp_header = (struct icmphdr*) (buffer+ip_header_length);
    fprintf(log_file, "\\n\\n@@@@@@@@@ICMP Packet@@@@@@@@@\\n");
    print_ip_header(buffer, size);
    fprintf(log_file, "\n");
    fprintf(log_file, "\n");
    fprintf(log_file, "ICMP HEADER\n");
    fprintf(log_file, "|---- TYPE -> %d\n", icmp_header->type);
    if (icmp_header->type == 11){
        fprintf(log_file, "TTL EXPIRED\n");
    } else if (icmp_header->type == ICMP_ECHOREPLY){
        fprintf(log_file, "|---- ICMP ECHO REPLY ONLY\n");
    }
    fprintf(log_file,"|------ CODE -> %d\n", icmp_header->code);
    fprintf(log_file,"|------ CHECKSUM -> %d\n", icmp_header->checksum);
    fprintf(log_file,"\n");

    fprintf(log_file,"IP Header\n");
    print_data_into_file(buffer,ip_header_length);

    fprintf(log_file,"UDP Header\n");
    print_data_into_file(buffer + ip_header_length , sizeof(icmp_header));

    fprintf(log_file,"Data Payload\n");
    print_data_into_file(buffer + ip_header_length + sizeof(icmp_header), (size - sizeof(icmp_header) - ip_header->ihl * 4));

}

void print_data_into_file(unsigned char* data, int size){
    for(i=0 ; i < size ; i++)
    {
        if( i!=0 && i%16==0)
        {
            fprintf(log_file,"         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(log_file,"%c",(unsigned char)data[j]);

                else fprintf(log_file,".");
            }
            fprintf(log_file,"\n");
        }

        if(i%16==0) fprintf(log_file,"   ");
        fprintf(log_file," %02X",(unsigned int)data[i]);

        if( i==size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) fprintf(log_file,"   ");

            fprintf(log_file,"         ");

            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) fprintf(log_file,"%c",(unsigned char)data[j]);
                else fprintf(log_file,".");
            }
            fprintf(log_file,"\n");
        }
    }
}



