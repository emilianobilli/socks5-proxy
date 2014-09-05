#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include "socks5.h"
#include "mem_types.h"
#include "mem_proto.h"
#include "sockets.h"


static int get_addr(u_int8_t atyp, void *msg, size_t msglen, struct sockname *addr  );

int
accept_proxy_client(struct tcp_socket *sk, struct tcp_socket_queue *skq)
{
    int sd;
    struct sockaddr_in  addr4;
    struct sockaddr_in6 addr6;
    struct tcp_socket *sk_ptr;


    if ( sk->kind == SOCKET_SERVER )
    {
	if (sk->family == AF_INET)
	{
	    sd = accept_tcp_ipv4(sk->socket, &addr4);    
	}
	else
	{
	    sd = accept_tcp_ipv6(sk->socket, &addr6);
	}
	if (sd != -1)
	{
	    sk_ptr = alloc_tcp_socket();
	    if (sk_ptr != NULL_TCP_SOCKET)
	    {
		sk_ptr->socket = sd;
		sk_ptr->state  = WAITING_METHODS;
		sk_ptr->kind   = SOCKET_PEER;
	    
		enqueue_tcp_socket(skq, sk_ptr);
	    }
	    else
	    {
		return -1;
	    }
	}
	else
	{
	    return -1;
	}
    }
    return 0;
}



int
manage_wmethods (struct tcp_socket *sk, int passwd)
{
    struct socks_auth *authhdr;
    struct msgbuff     *msg;
    u_int8_t           buffer[WMETHODS_BUFFER] = {0};
    ssize_t            msglen;
    u_int8_t	       i, nm;		
    u_int8_t	       method = NOTACCEPT;
    u_int8_t	       *mptr;
    
    if ( sk->kind == SOCKET_PEER && sk->state == WAITING_METHODS )
    {
	errno = 0;
	msglen = recv(sk->socket, buffer, WMETHODS_BUFFER, MSG_DONTWAIT);
	if ( msglen > 0 ) 
	{
	    authhdr = (struct socks_auth *)&buffer[0];
	    if ( authhdr->ver == 0x05 )
	    {
		nm   = authhdr->md.nmethod;
		mptr = &buffer[SZS5AUTH];
		if (passwd)
		{
		    
		    for (i=0; i <= nm-1 && i < WMETHODS_BUFFER-SZS5AUTH; i++)
			if (mptr[i] == USERPASS)
			    method = USERPASS;
	
		}
		else
		{
		    for (i=0; i <= nm-1 && i < WMETHODS_BUFFER-SZS5AUTH; i++)
			if (mptr[i] == NO_AUTH)
			    method = NO_AUTH;
		}	

		msg = alloc_msg_buffer(2);

		if ( msg != NULL )
		{

		    authhdr = (struct socks_auth *)msg->buffer;
		    authhdr->ver = 0x05;
		    authhdr->md.method = method;
		    enqueue_pending_msg(&(sk->msgq), msg);

		    if ( method == USERPASS )
		    {
			sk->state = WAITING_USERPASS;
		    }
		    else if (method == NO_AUTH)
		    {
			sk->state = PENDING_SND_METHOD;
		    }
		    else
		    {
			sk->state = WAITING_CLOSE;
		    }
		}
		else
		    return -1;
	    
	    }
	    else
	    {
		sk->state = CLOSE;
	    }
	}
	else 
	{
	    if (msglen == -1 && (errno != EINTR || errno != EAGAIN ) )
		return -1;
	}
    }	
    return 0;
}





int 
manage_wrequest (struct tcp_socket *sk, struct tcp_socket_queue *skq)
{
    struct socks_hdr   *hdr;
    struct sockaddr_in  addr4;
    struct sockaddr_in6 addr6;
    struct sockname     sockname;
    struct tcp_socket   *sk_ptr;
    int 		sd;
    u_int8_t 		buffer[WREQUEST_BUFFER];
    
    ssize_t msglen;

    if ( sk->kind == SOCKET_PEER && sk->state == WAITING_REQUEST )
    {

	msglen = recv(sk->socket, buffer, WREQUEST_BUFFER, MSG_DONTWAIT);

	if ( msglen > 0 )
	{
	    hdr = (struct socks_hdr *) &buffer[0];
	    if ( hdr->ver != 0x05 )
	    {
		sk->state = CLOSE;
		return 0;
	    }    
	    if ( hdr->kind.cmd == BIND )
	    {
		sk->state = CLOSE;
		return 0;    
	    }
	    else if ( hdr->kind.cmd == CONNECT )
	    {
		errno = 0;
		get_addr(hdr->atyp, 
		         &buffer[SZS5HDR], 
		         msglen - SZS5HDR, 
		         &sockname);
		
		if ( sockname.family == AF_INET )
		{
		    addr4.sin_family = AF_INET;
		    addr4.sin_port   = sockname.port;
		    memcpy(&addr4.sin_addr.s_addr, &sockname.in.addr4, 4);
	
		    sd = connect_tcp_ipv4(&addr4,1);
		    
		    sk_ptr = alloc_tcp_socket();
		    if ( sk_ptr != NULL_TCP_SOCKET )
		    {
			sk_ptr->socket = sd;
			sk_ptr->state  = CONNECTING;
		        sk_ptr->kind   = SOCKET_PEER;    
			sk->peer       = sk_ptr;
		        sk_ptr->peer   = sk;
		        sk->state      = WAITING_PEER;    
			enqueue_tcp_socket(skq, sk_ptr);	
		    }
		    else
		    {
			return -1;
		    }		
		}    	
		else
		{
		    addr6.sin6_family = AF_INET6;
		    addr6.sin6_port   = sockname.port;
		    memcpy(&addr6.sin6_addr.s6_addr, &sockname.in.addr6, 16);

		    sd = connect_tcp_ipv6(&addr6,1);
		        
		    sk_ptr = alloc_tcp_socket();
		    if ( sk_ptr != NULL_TCP_SOCKET )
		    {
		        sk_ptr->socket = sd;
		        sk_ptr->state  = CONNECTING;
		        sk_ptr->kind   = SOCKET_PEER;    
			sk->peer       = sk_ptr;
			sk_ptr->peer   = sk;
			sk->state      = WAITING_PEER;    
			enqueue_tcp_socket(skq, sk_ptr);	
		    }
		    else
		    {
			return -1;
		    }
		}
	    }
	}
    }
    return 0;
}
		    
		    


int 
manage_wusepass (struct tcp_socket *sk)
{
    return 0;
}

int 
manage_pipeline (struct tcp_socket *sk)
{
    struct msgbuff *msg;
    ssize_t msglen;

    errno = 0;    
    msg = alloc_msg_buffer(1024*8);
    
    if (msg != NULL)
    {
	msglen = recv(sk->socket, msg->buffer, 1024*8, MSG_DONTWAIT);
	if ( msglen > 0 )
	{
	    msg->nrbytes = msglen;
	    enqueue_pending_msg(&(sk->peer->msgq), msg);
	}
	else if ( msglen == 0 )
	{
	    free_msg_buffer(msg);
	    sk->state = CLOSE;
	    if (sk->peer)
	    {
		sk->peer->state = WAITING_CLOSE;
	    }
	    sk->peer = NULL_TCP_SOCKET;
	}
	else 
	{
	    if (msglen == -1 && errno != EINTR)
		return -1;
	}    
    }	
    else
    {
	return -1;
    }
    return 0;
}

int 
manage_wconnect (struct tcp_socket *sk)
{
    int sd;
    struct sockaddr_in  addr4;
    struct sockaddr_in6 addr6;
    struct socks_hdr    *hdr;
    struct msgbuff      *msg;
    
    if ( sk->kind == SOCKET_PASV && sk->state == WAITING_CONNECTION )
    {
	errno = 0;
	if ( sk->family == AF_INET )
	{
	    sd = accept_tcp_ipv4(sk->socket, &addr4);
	    if ( sd != -1 ) 
	    {
		sk->kind         = SOCKET_PEER;
	        sk->state        = PIPELINE;
	        sk->peer->state  = PIPELINE;
	        close(sk->socket);
	        sk->socket      = sd;
	    
		msg = alloc_msg_buffer(SZS5HDR + 4 + 2);
		if (msg != NULL)
		{ 
		    hdr = (struct socks_hdr *) msg->buffer;
		    hdr->ver = 0x05;
		    hdr->kind.rep = SUCCESS;
		    hdr->rsv      = 0x00;
		    hdr->atyp     = IPV4ADDR;
		    memcpy(&((u_int8_t *)(msg->buffer))[SZS5HDR], &addr4.sin_addr.s_addr, 4);
		    memcpy(&((u_int8_t *)(msg->buffer))[SZS5HDR+4], &addr4.sin_port, 2);
		    enqueue_pending_msg(&(sk->peer->msgq), msg);
		}
		else
		    return -1;
	    }
	    else
	    {
		if (errno != EINTR)
		    return -1;
	    }
	}
	else if ( sk->family == AF_INET6 )
	{
	    sd = accept_tcp_ipv6(sk->socket, &addr6);
	    if ( sd != -1 ) 
	    {
		sk->kind         = SOCKET_PEER;
	        sk->state        = PIPELINE;
	        sk->peer->state  = PIPELINE;
	        close(sk->socket);
	        sk->socket      = sd;
		msg = alloc_msg_buffer(SZS5HDR + 16 + 2);
		if (msg != NULL)
		{ 
		    hdr = (struct socks_hdr *) msg->buffer;
		    hdr->ver = 0x05;
		    hdr->kind.rep = SUCCESS;
		    hdr->rsv      = 0x00;
		    hdr->atyp     = IPV6ADDR;
		    memcpy(&((u_int8_t *)(msg->buffer))[SZS5HDR], &addr6.sin6_addr.s6_addr, 16);
		    memcpy(&((u_int8_t *)(msg->buffer))[SZS5HDR+16], &addr6.sin6_port, 2);
		    enqueue_pending_msg(&(sk->peer->msgq), msg);
		}
	    }
	    else
	    {
		if (errno != EINTR)
		    return -1;
	    }
	}
	
    }
    return 0;
}


int 
read_all(struct tcp_socket_queue *all, struct tcp_socket_queue *rcv_queue)
{
    struct tcp_socket *sk_ptr;
    
    
    
    while ( ( sk_ptr = dequeue_rdy_recv(rcv_queue) ) != NULL )
    {
	if (sk_ptr->kind == SOCKET_SERVER)
	{
	    if (accept_proxy_client(sk_ptr, all) == -1)
	    {
		return -1;
	    }
	}
	else
	{
	    if (sk_ptr->state == WAITING_METHODS)
	    {
		if (manage_wmethods(sk_ptr, 0) == -1)
		{
		    return -1;
		}
	    }
	    else if (sk_ptr->state == WAITING_REQUEST)
	    {
		if (manage_wrequest(sk_ptr, all) == -1)
		{
		    return -1;
		}
	    }
	    else if (sk_ptr->state == PIPELINE)
	    {
		if (manage_pipeline(sk_ptr) == -1)
		{
		    return -1;
		}
	    }
	}
    }
    return 0;
}	



ssize_t
flush_all (struct tcp_socket_queue *snd_queue)
{
    struct tcp_socket *ptr;
    struct msgbuff    *msg;
    ssize_t slen;
    ssize_t flushlen = 0;
    
    while ( (ptr = dequeue_rdy_send(snd_queue)) != NULL_TCP_SOCKET )
    {
	msg = dequeue_pending_msg(&(ptr->msgq));
	if ( msg != NULL )
	{
	    errno = 0;
	    slen = send(ptr->socket, &((u_int8_t *)(msg->buffer))[msg->offset], msg->nrbytes - msg->offset, MSG_DONTWAIT);
	    if ( slen != -1 )
	    {

		if ( slen == msg->nrbytes )
		{
		    free_msg_buffer(msg);
		    if ( ptr->state == PENDING_SND_METHOD )
			ptr->state = WAITING_REQUEST;
		    if ( ptr->state == PENDING_SND_REPLY  )
			ptr->state = PIPELINE;
		    
		    if ( ptr->state == WAITING_CLOSE && !queue_filled(&(ptr->msgq))) 
			ptr->state = CLOSE;

		}
		else
		{
		    msg->offset  += slen;
		    push_pending_msg(&(ptr->msgq), msg);
		    continue;
		}
		flushlen += slen;
	    }
	    else
	    {
		switch (errno)
		{
		    case ECONNRESET:

			ptr->state = CLOSE;
			if ( ptr->peer )
			    ptr->peer->state = CLOSE;

			break;		

		    case EINTR:

			continue;

		    default:
			return -1;
			break;
		}
	    }
	}
    }
    return flushlen;
}

int 
tcp_socket_select (struct tcp_socket_queue *all, struct tcp_socket_queue *send_q, struct tcp_socket_queue *recv_q, struct timeval *timeout )
{
    int retval  = 0;
    int maxfd   = -1;
    int counter = 0;
    int n;

    struct tcp_socket *ptr = NULL_TCP_SOCKET;
    fd_set recvset;
    fd_set sendset;
    fd_set *recvts;
    fd_set *sendts;

    FD_ZERO(&recvset);
    FD_ZERO(&sendset);
    
    if (all != NULL)
    {
	ptr = all->head;
	while ( ptr != NULL_TCP_SOCKET )
	{
	    if ( ptr->kind == SOCKET_SERVER || ptr->kind == SOCKET_PASV )
	    {
		maxfd = (maxfd > ptr->socket) ? maxfd : ptr->socket;
		FD_SET(ptr->socket, &recvset);
		counter++;
	    }
	    else
	    {
		if ( ptr->state == WAITING_METHODS || 
		     ptr->state == WAITING_REQUEST || 
		     ptr->state == WAITING_USERPASS )
		{
		    maxfd = (maxfd > ptr->socket) ? maxfd : ptr->socket;
		    FD_SET(ptr->socket, &recvset);
		    counter++;
		}
		else if ( ptr->state == PIPELINE )
		{
		    maxfd = (maxfd > ptr->socket) ? maxfd : ptr->socket;
		    FD_SET(ptr->socket, &recvset);
		    counter++;
		    
		    if ( queue_filled(&(ptr->msgq)) )
		    {
			FD_SET(ptr->socket, &sendset);
		    }
		}
		else if ( ptr->state == WAITING_CLOSE )
		{
		    if ( queue_filled(&(ptr->msgq)) )
		    {
			maxfd = (maxfd > ptr->socket) ? maxfd : ptr->socket;
		        FD_SET(ptr->socket, &sendset);
		        counter++;
		    }
		}
		else if ( ptr->state == PENDING_SND_METHOD )
		{
		    if ( queue_filled(&(ptr->msgq)) )
		    {
			maxfd = (maxfd > ptr->socket) ? maxfd : ptr->socket;
		        FD_SET(ptr->socket, &sendset);
		        counter++;
		    }
		}
		else if ( ptr->state == PENDING_SND_REPLY )
		{
		    if ( queue_filled(&(ptr->msgq)) )
		    {
			maxfd = (maxfd > ptr->socket) ? maxfd : ptr->socket;
		        FD_SET(ptr->socket, &sendset);
		        counter++;
		    }
		
		}	    
	    }
	    ptr = ptr->next;
	}
	recvts = (recv_q != NULL) ? &recvset : NULL;
	sendts = (send_q != NULL) ? &sendset : NULL;
    
	if (counter == 0)
	    return 0;
	
	n = select(maxfd+1, recvts, sendts, NULL, timeout);
	if ( n == -1 )
	    retval = -1;
	else
	{
	    ptr = all->head;
	    
	    if ( recv_q != NULL ) 
	    {
		recv_q->head = NULL_TCP_SOCKET;
	        recv_q->tail = NULL_TCP_SOCKET;
	    }
	    if ( send_q != NULL )
	    {
		send_q->head = NULL_TCP_SOCKET;
	        send_q->tail = NULL_TCP_SOCKET;
	    }
	    while ( ptr != NULL_TCP_SOCKET )
	    {
		if ( send_q != NULL )
		{
		    if (FD_ISSET(ptr->socket, sendts))
		    {
			enqueue_rdy_send(send_q, ptr);
		    }	
		}
		if ( recv_q != NULL )
		{
		    if (FD_ISSET(ptr->socket, recvts))
		    {
			enqueue_rdy_recv(recv_q, ptr);
		    }
		}	
		ptr = ptr->next;
	    }
	}
    } 
    return retval;
}


int check_connection (struct tcp_socket_queue *skq)
{
    struct sockaddr_in  addr4;
    struct sockaddr_in6 addr6;
    struct tcp_socket 	*sk_ptr;
    struct msgbuff    	*msg;
    struct socks_hdr  	*hdr;
    socklen_t		addrlen;

    int so_error;
    
    sk_ptr = skq->head; 

    while ( sk_ptr != NULL )
    {
	if ( sk_ptr->state == CONNECTING )
	{
	    get_so_error(sk_ptr->socket, &so_error);
	    
	    if ( so_error == 0 )
	    {
		if (sk_ptr->family == AF_INET )
		{
		    addrlen = sizeof(struct sockaddr_in);    
		    if ( getsockname(sk_ptr->socket, (struct sockaddr *)&addr4, &addrlen) == -1 )
		    {
		        sk_ptr->state = CLOSE;
		        msg = alloc_msg_buffer(4);
		        if ( msg != NULL )
			{
		    	    hdr = (struct socks_hdr *)msg->buffer;
		    	    hdr->ver      = 0x05;
		    	    hdr->kind.rep = SFAILURE;
		    	    hdr->rsv      = 0x00;
		    	    msg->offset   = 0;
		    	    msg->nrbytes  = 4;
		    	    sk_ptr->peer->state = WAITING_CLOSE;
		    	    enqueue_pending_msg(&(sk_ptr->peer->msgq), msg);
			}
			else
			{
			    return -1;
					         			
			}
		    }
		    else
		    {
			msg = alloc_msg_buffer(4 + 4 + 2);
			if ( msg != NULL )
		    	{
		    	    hdr = (struct socks_hdr *)msg->buffer;
		    	    hdr->ver      = 0x05;
		    	    hdr->kind.rep = SUCCESS;
		    	    hdr->rsv      = 0x00;
		    	    hdr->atyp	  = IPV4ADDR;
		    	    msg->offset   = 0;
		    	    msg->nrbytes  = 4 + 4 + 2;
		    	    memcpy( &((u_int8_t *)(msg->buffer))[SZS5HDR], &addr4.sin_addr.s_addr, 4 );
		    	    memcpy( &((u_int8_t *)(msg->buffer))[SZS5HDR+ 4], &addr4.sin_port, 2 );
		    	    enqueue_pending_msg(&(sk_ptr->peer->msgq), msg);
	    		    sk_ptr->state = PIPELINE;
	    		    sk_ptr->peer->state = PENDING_SND_REPLY;
	    		}
			else
			{
			    return -1;
			}
		    }
		}
		else
		{
		    addrlen = sizeof(struct sockaddr_in6);    
		    if ( getsockname(sk_ptr->socket, (struct sockaddr *)&addr6, &addrlen) == -1 )
		    {
		        sk_ptr->state = CLOSE;
		        msg = alloc_msg_buffer(4);
		        if ( msg != NULL )
			{
		    	    hdr = (struct socks_hdr *)msg->buffer;
		    	    hdr->ver      = 0x05;
		    	    hdr->kind.rep = SFAILURE;
		    	    hdr->rsv      = 0x00;
		    	    msg->offset   = 0;
		    	    msg->nrbytes  = 4;
		    	    sk_ptr->peer->state = WAITING_CLOSE;
		    	    enqueue_pending_msg(&(sk_ptr->peer->msgq), msg);
			}
			else
			{
			    return -1;
					         			
			}
		    }
		    else
		    {
			msg = alloc_msg_buffer(4 + 16 + 2);
			if ( msg != NULL )
		    	{
		    	    hdr = (struct socks_hdr *)msg->buffer;
		    	    hdr->ver      = 0x05;
		    	    hdr->kind.rep = SUCCESS;
		    	    hdr->rsv      = 0x00;
		    	    hdr->atyp	  = IPV4ADDR;
		    	    msg->offset   = 0;
		    	    msg->nrbytes  = 4 + 16 + 2;
		    	    memcpy( &((u_int8_t *)(msg->buffer))[SZS5HDR], &addr6.sin6_addr.s6_addr, 16 );
		    	    memcpy( &((u_int8_t *)(msg->buffer))[SZS5HDR+ 16], &addr6.sin6_port, 2 );
		    	    enqueue_pending_msg(&(sk_ptr->peer->msgq), msg);
	    		    sk_ptr->state = PIPELINE;
	    		    sk_ptr->peer->state = PENDING_SND_REPLY;
	    		}
			else
			{
			    return -1;
			}
		    }
		}
	    }
	    else if ( so_error != EALREADY && so_error != EINPROGRESS )
	    {
		msg = alloc_msg_buffer(4);
		if ( msg != NULL )
		{
		    hdr = (struct socks_hdr *)msg->buffer;
		    hdr->ver      = 0x05;
		    hdr->kind.rep = SFAILURE;
		    hdr->rsv      = 0x00;
		    msg->offset   = 0;
		    msg->nrbytes  = 4;
		    sk_ptr->peer->state = WAITING_CLOSE;
		    enqueue_pending_msg(&(sk_ptr->peer->msgq), msg);
		}
		else
		{
		    return -1;
		}
	    }
	}    
	sk_ptr = sk_ptr->next;
    }
    return 0;
}


int 
get_addr(u_int8_t atyp, void *msg, size_t msglen, struct sockname *addr  )
{
    struct   hostent *host;
    u_int8_t hostlen;
    u_int8_t *hostname;
    u_int8_t *msg_ptr;
    
    msg_ptr = (u_int8_t *) msg;

    if (atyp == DOMAINNAME)
    {
        hostname = msg_ptr;
        hostlen  = hostname[0];
        hostname++;
        if (msglen == (hostlen + 1 + 2))
        {
    	    memcpy(&(addr->port), &hostname[hostlen],2);
	    hostname[hostlen] = 0x00;
	    host = gethostbyname((char *)hostname);
	    if ( host != NULL )
	    {
	        if ( (addr->family = host->h_addrtype) == AF_INET )
	    	    memcpy(&(addr->in.addr4.s_addr), host->h_addr_list[0], 4);
		else
		    memcpy(&(addr->in.addr6.s6_addr), host->h_addr_list[0], 16);
	    }
	    else
	    {
	        return -1;
	    }
	}
	else
	{
	    return -1;	    
	}
    }	    
    else if (atyp == IPV4ADDR)
    {
        if (msglen == 4 + 2)
        {
    	    addr->family = AF_INET;
	    memcpy(&(addr->in.addr4.s_addr), msg_ptr, 4);
	    memcpy(&(addr->port), &msg_ptr[4], 2);
	}
	else
	{
	    return -1;
	} 
    }
    else if (atyp == IPV6ADDR)
    {
        if (msglen == 16 + 2)
        {
    	    addr->family = AF_INET6;
	    memcpy(&(addr->in.addr6.s6_addr), msg_ptr, 16);
	    memcpy(&(addr->port), &msg_ptr[16], 2);
	}
	else
	{
	    return -1;    
	}
    }
    else
    {
        return -1;
    }
            
    return 0;
}



