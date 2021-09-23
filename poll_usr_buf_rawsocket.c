#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>
#include <string.h>
#include <poll.h>
#include <getopt.h>
#include <signal.h>
#include <sys/signal.h>
#include <sys/signalfd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>




#define MAX_POLLFDS 2
#define MAX_PACKET_SIZE 256

int main(int argc, char *argv[]){
    struct pollfd pollfds[MAX_POLLFDS];
    struct signalfd_siginfo siginfo;
    int sfd,sock;
    uint16_t  port=0;
    char process_name[256];//fetch port via process_name TODO
    bool debug_enable=false;
    int saddr_size;
    struct sockaddr saddr;
    char buffer[MAX_PACKET_SIZE];
    char iface_name[IFNAMSIZ];
    int pollidx = 0;
    int ret = -1;
    memset(iface_name,0x00,IFNAMSIZ);

    //option processing
    {
        int opt;
        int val = 0;

        while ((opt = getopt(argc, argv, "-:i:p:n:d")) != -1) 
        {
           switch (opt) 
           {
            case 'd':
              debug_enable=true;
              printf("enable debug\n");
              break;
            case 'i':
              if(debug_enable){
                 printf("optarg: %s \n", optarg);
                 printf("iface_name: %s iface_name_stringlen: %ld\n", iface_name,strlen(iface_name));
              }
              memcpy(&iface_name[0],optarg,strlen(optarg));
              break;
            case 'p':
                errno = 0;
                if( (val = strtoul(optarg,NULL,10)) > 65535)
                {
                  fprintf(stderr,"Port value %d out of range\n",val);
                  exit(-1);
                }
                errno = 0;
                port =(uint16_t) strtoul(optarg,NULL,10);

                if (errno != 0) {
                  perror("strtoul");
                  exit(EXIT_FAILURE);
                }

                if(debug_enable)
                  printf("port: %d\n", port);

              break;
            case 'n':
              printf("process name to copy packet data: %s\n", optarg);
              break;
            case ':':
              printf("Missing arg for %c\n", optopt);
              break;
            case '?':
              printf("Unknown option: %c\n", optopt);
              exit(-1);
            case 1:
              printf("Non-option arg: %s\n", optarg);
              exit(-1);
           }
        }
        if(!port || (strlen(iface_name)==0)){
            printf("option -p and -i arugments are required,exiting\n");
            exit(-1);
        }
    }

    printf("done args processing\n");
    //pollfd and sfd implementation
    {
      sigset_t mask;

      /* We will handle SIGTERM and SIGINT. */
      sigemptyset (&mask);
      sigaddset (&mask, SIGTERM);
      sigaddset (&mask, SIGINT);

      /* Block the signals thet we handle using signalfd(), so they don't
       * cause signal handlers or default signal actions to execute. */
      if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
        perror ("sigprocmask");
        return 1;
      }
      /* Create a file descriptor from which we will read the signals. */
      sfd = signalfd (-1, &mask, 0);
      if (sfd < 0) {
        perror ("signalfd");
        return 1;
      }
      pollfds[pollidx].fd = sfd;
      pollfds[pollidx++].events = POLLIN | POLLERR | POLLHUP;
    }  

    /*raw socket creation*/
    {  
        struct sockaddr_ll sll;
        struct packet_mreq mr;
	struct ifreq ifr;
       
        memset(buffer,0x00,sizeof(buffer));
        struct sock_filter src_port_filter[] = {{ 0x28, 0, 0, 0x0000000c },
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
        int totinsns = sizeof(src_port_filter)/sizeof(src_port_filter[0]);
        if(debug_enable)
          printf("# of insns %d\n",totinsns);

        struct sock_fprog bpf_program = {sizeof(src_port_filter)/sizeof(src_port_filter[0]), src_port_filter};
        //sock = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
        sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

        if(sock < 0){
            perror("socket() failed");
            return -1;
        }

        memset(&ifr, 0, sizeof(ifr));
	strncpy((char *)ifr.ifr_name, iface_name, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl: SIOCGIFINDEX %s\n");
		close(sock);
		return -1;
	}

        memset(&sll,0,sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface_name);
        sll.sll_protocol = htons(ETH_P_ALL);
        if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
          perror("bind() failed");
          close(sock);
          return -1;
        }
       
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
        pollfds[pollidx].fd = sock;
        pollfds[pollidx++].events = POLLIN | POLLERR | POLLHUP;
    }

    int count = 0;
    if(debug_enable)
       printf("pollidx=%d\n",pollidx);

    while(1){
      saddr_size = sizeof(saddr);
      pollfds[0].revents = 0;
      pollfds[1].revents = 0;
      //poll no poll timeout, just get when you receive the event
      ret = poll(pollfds, pollidx,-1);
      if ( ret < 0) {
          perror("poll()");
      }
      if ( ret == 0) {
          fprintf(stdout,"poll timedout");
      }

      /* Check if a signal was received. */
      if (pollfds[0].revents & POLLIN) {
          printf("got signal\n");
          if (read(sfd, &siginfo, sizeof(siginfo)) != sizeof(siginfo)) {
            perror("read() error in signalfd read");
          }
          printf("%s: got signal %d\n",argv[0],siginfo.ssi_signo);
          break;
      }

      /* Check if pollfd got the event for recvfrom, this is not working, needs more debugging. */
      if (pollfds[1].revents & POLLIN) {
          printf("got packet data\n");
          if(recvfrom(sock,buffer, MAX_PACKET_SIZE,0,&saddr,(socklen_t *)&saddr_size) < 0){
              perror("recvfrom(): error");
              break;
          }
          printf("count=%d\n",count);
          count = 0;
      }
    }
    int val = 0;
    setsockopt(sock, SOL_SOCKET, SO_DETACH_FILTER, &val, sizeof(val));
    if(sfd)
      close(sfd);
    if(sock)
      close(sock);
    exit(EXIT_SUCCESS);
}
