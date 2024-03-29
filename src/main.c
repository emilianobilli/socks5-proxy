#include "mem_types.h"
#include "mem_proto.h"
#include "sockets.h"
#include "socks5.h"
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/time.h>

int main(void)
{
    int sd;
    struct sockaddr_in addr;
    struct tcp_socket *sk_ptr;
    struct tcp_socket_queue all,qrecv,qsend;
    struct timeval t;
    int n;
    
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(1080);
    
    inet_aton("192.168.1.16", &addr.sin_addr.s_addr);
    
          
    fflush(stdout);
    sd = bind_tcp_ipv4(&addr, 128*1024, 128*1024);
    
    
    if (sd == -1)
    {
	perror("bind_tcp_ipv4");
	return -1;
    }
    
    sk_ptr = alloc_tcp_socket();
    if (sk_ptr == NULL)
    {
	close(sd);
	perror("alloc_tcp_socket()");
	return -1;
    }

    sk_ptr->socket = sd;
    sk_ptr->kind   = SOCKET_SERVER;
    sk_ptr->state  = 0x00;
    sk_ptr->next   = NULL;
    
    all.head = NULL;
    all.tail = NULL;
    qsend.head = NULL;
    qsend.tail = NULL;
    qrecv.head = NULL;
    qrecv.tail = NULL;
    
    enqueue_tcp_socket(&all, sk_ptr);

        
    while (1)
    {
	t.tv_sec = 0;
	t.tv_usec = 200000;
	
	if (tcp_socket_select(&all, &qsend, &qrecv, &t) == -1)
	{
	    perror("1");
	    return -1;
	}

	if (read_all(&all,&qrecv) == -1)
	{
	    perror("2");
	    return -1;
	}
	
	if (flush_all(&qsend) == -1)
	{
	    perror("3");
	    return -1;
	}
	
    }
    
    return 0;
}


