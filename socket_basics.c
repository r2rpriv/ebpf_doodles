#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <string.h> /* superset of previous */
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include "rlimit_header.h"

#define MAX_PACKET_SIZE 8192

void printPayload(char *buff,int size){
  char str[MAX_PACKET_SIZE];
  int printed = snprintf(str,size,"%s",buff);
  printf("received %d bytes, printed %d\n",size,printed);
  printf("buffer %s\n",str);
}

int main(int argc,char **argv){
  int count = 0;
  int ret = -1;
  int saddr_size;
  struct sockaddr saddr;
  struct sockaddr_ll sll;
  struct packet_mreq mr;
  struct ifreq ifr;
  char buffer[MAX_PACKET_SIZE];

  memset(buffer,0x00,sizeof(buffer));
  struct sock_filter dst_port_filter[] = {{ 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 6, 0x000086dd },
    { 0x30, 0, 0, 0x00000014 },
    { 0x15, 2, 0, 0x00000084 },
    { 0x15, 1, 0, 0x00000006 },
    { 0x15, 0, 13, 0x00000011 },
    { 0x28, 0, 0, 0x00000038 },
    { 0x15, 10, 11, 0x00001f90 },
    { 0x15, 0, 10, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 2, 0, 0x00000084 },
    { 0x15, 1, 0, 0x00000006 },
    { 0x15, 0, 6, 0x00000011 },
    { 0x28, 0, 0, 0x00000014 },
    { 0x45, 4, 0, 0x00001fff },
    { 0xb1, 0, 0, 0x0000000e },
    { 0x48, 0, 0, 0x00000010 },
    { 0x15, 0, 1, 0x00001f90 },
    { 0x6, 0, 0, 0x00040000 },
    { 0x6, 0, 0, 0x00000000 },};

  //tcpdump -dd dst port 8080
  int totinsns = sizeof(dst_port_filter)/sizeof(dst_port_filter[0]);
  printf("# of insns %d\n",totinsns);
  struct sock_fprog bpf_program = {sizeof(dst_port_filter)/sizeof(dst_port_filter[0]), dst_port_filter};
  int sock = socket(AF_PACKET, SOCK_RAW|SOCK_CLOEXEC, htons(ETH_P_ALL));

  if(sock < 0){
      perror("socket() failed");
      return -1;
  }

  //iface
  memset(&ifr, 0, sizeof(ifr));
  strncpy((char *)ifr.ifr_name, "lo", IFNAMSIZ);
  if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
  	perror("ioctl: SIOCGIFINDEX %s\n");
  	close(sock);
  	return -1;
  }

  //attach iface for socket bind
  memset(&sll,0,sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = if_nametoindex("lo");
  sll.sll_protocol = htons(ETH_P_ALL);

  if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
    perror("bind() failed");
    close(sock);
    return -1;
  }

  //set promisc mode
  memset(&mr, 0, sizeof(mr));
  mr.mr_ifindex = ifr.ifr_ifindex;
  mr.mr_type = PACKET_MR_PROMISC;

  if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
  	printf("set_promisc: %s\n", strerror(errno));
  	close(sock);
  	return -1;
  }
  ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_program, sizeof(bpf_program));

  if ( ret != 0 ) {
    perror ("setsockopt() init filter attach failed");
    return -1;
  }

  int csum_disable=1;
  ret = setsockopt(sock, SOL_SOCKET, SO_NO_CHECK, &csum_disable, sizeof(csum_disable));

  if ( ret != 0 ) {
    perror ("setsockopt() checksumdisable failed");
    return -1;
  }
  saddr_size = sizeof(saddr);
  printf("going to start capture\n");
  while(1){
    saddr_size = sizeof(saddr);
    count = recvfrom(sock,buffer, MAX_PACKET_SIZE,0,&saddr,(socklen_t *)&saddr_size);
    if ( count == -1){
      break;
    }
    printf("size of buffer %d",(int)strlen(buffer));
    printPayload(buffer,count);
    count = 0;
  }
  int val = 0;
  setsockopt(sock, SOL_SOCKET, SO_DETACH_FILTER, &val, sizeof(val));
  close(sock);
}
