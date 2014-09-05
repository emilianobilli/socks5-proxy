#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

extern int accept_tcp_ipv4 (int sk, struct sockaddr_in *addr);

extern int accept_tcp_ipv6 (int sk, struct sockaddr_in6 *addr);

extern int bind_tcp_ipv4 (struct sockaddr_in *addr);

extern int bind_tcp_ipv6 (struct sockaddr_in6 *addr);

extern int connect_tcp_ipv4 (struct sockaddr_in *addr, int nonblock);

extern int connect_tcp_ipv6 (struct sockaddr_in6 *addr, int nonblock);

extern int iptos_throughput(int socket);

extern int tcp_cork(int socket);

extern int tcp_nodelay(int socket);

extern int tcp_window_clamp(int socket, u_int32_t ww_clamp );

extern int tcp_rcvbuf(int socket, u_int32_t buff_size );

extern int tcp_sndbuf(int socket, u_int32_t buff_size );

extern int tcp_reuseaddr(int socket);


