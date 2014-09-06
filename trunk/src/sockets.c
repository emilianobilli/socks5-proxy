#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>

int 
accept_tcp_ipv4 (int sk, struct sockaddr_in *addr)
{
    socklen_t len = sizeof(struct sockaddr_in);
    
    return accept(sk, (struct sockaddr *)addr, &len);
}


int 
accept_tcp_ipv6 (int sk, struct sockaddr_in6 *addr)
{
    socklen_t len = sizeof(struct sockaddr_in6);
    
    return accept(sk, (struct sockaddr *)addr, &len);
}


int 
bind_tcp_ipv4 (struct sockaddr_in *addr)
{
    int sd;
    socklen_t len;
    
    if ((sd =socket(PF_INET, SOCK_STREAM, 0))== -1)
    {
	return -1;
    }
    
    if (tcp_reuseaddr(sd) == -1)
    {
	printf("mmm");
	close(sd);
	return -1;
    }
    

    len = sizeof(struct sockaddr_in);
    
    if (bind(sd, (struct sockaddr *) addr, len) == -1)
    {
	close(sd);
	return -1;
    }

    if (listen(sd, 20) == -1)
    {
	close(sd);
	return -1;
    }
    return sd;
}

int 
bind_tcp_ipv6 (struct sockaddr_in6 *addr)
{
    int sd;
    socklen_t len;
    
    if ((sd =socket(PF_INET6, SOCK_STREAM, 0))== -1)
    {
	return -1;
    }

    if (tcp_reuseaddr(sd) == -1)
    {
	close(sd);
	return -1;
    }
    
    len = sizeof(struct sockaddr_in6);
    
    if (bind(sd, (struct sockaddr *) addr, len) == -1)
    {
	close(sd);
	return -1;
    }
    if (listen(sd, 20) == -1)
    {
	close(sd);
	return -1;
    }
    return sd;
}


int 
connection_status (int socket, int *so_error)
{
    socklen_t len;
    
    len = sizeof(int);
    
    return getsockopt(socket, SOL_SOCKET, SO_ERROR, so_error, &len);
}


int 
connect_tcp_ipv4 (struct sockaddr_in *addr, int nonblock)
{
    int sd;
	
    errno = 0;
	    
    if ((sd = socket(PF_INET, SOCK_STREAM, 0)) == -1) 
    {
        return -1;
    }    

    if (nonblock)
    {
	if (fcntl(sd, F_SETFL, O_NONBLOCK) == -1)
	    return -1;
    }

    if (connect(sd, (struct sockaddr *)addr, sizeof(struct sockaddr_in)) == -1) 
    {			
	if (errno != EINPROGRESS) 
	{
	    close(sd);
	    return -1;
	}
    }
    return sd;
}

int 
connect_tcp_ipv6 (struct sockaddr_in6 *addr, int nonblock)
{
    int sd;
    
    errno = 0;
	    /* Crea el zocalo */
    if ((sd = socket(PF_INET6, SOCK_STREAM, 0)) == -1)
    {
        return -1;
    }
    
    if (nonblock)
    {
	if (fcntl(sd, F_SETFL, O_NONBLOCK) == -1)
	    return -1;
    }
    	    
    if (connect(sd, (struct sockaddr *)addr, sizeof(struct sockaddr_in6)) == -1)
    {
	if (errno != EINPROGRESS) 
	{
	    close(sd);
	    return -1;
	}
    }
    	
    return sd;
}

int
iptos_throughput(int socket)
{
    int tos = IPTOS_THROUGHPUT;
    return setsockopt(socket, IPPROTO_IP, IP_TOS, &tos, sizeof(int));
}

int
tcp_cork(int socket)
{
    int flag = 1;
    return setsockopt(socket, IPPROTO_TCP, TCP_CORK, &flag, sizeof(int));
}

int
tcp_nodelay(int socket)
{
    int flag = 1;
    return setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));
}

int 
tcp_window_clamp(int socket, u_int32_t ww_clamp )
{
    return setsockopt(socket, IPPROTO_TCP, TCP_WINDOW_CLAMP, &ww_clamp, sizeof(u_int32_t));
}

int
tcp_rcvbuff(int socket, u_int32_t buff_size )
{
    return setsockopt(socket, SOL_SOCKET, SO_RCVBUF, &buff_size, sizeof(u_int32_t));
}

int
tcp_sndbuff(int socket, u_int32_t buff_size )
{
    return setsockopt(socket, SOL_SOCKET, SO_SNDBUF, &buff_size, sizeof(u_int32_t));
}

int
tcp_reuseaddr(int socket)
{
    int flag = 1;
    return setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(int));
}

int 
tcp_queue_len(int socket, u_int32_t *qlen)
{
    return ioctl(socket, SIOCINQ, qlen);
}
