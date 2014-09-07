#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

extern int accept_tcp_ipv4 (int sk, struct sockaddr_in *addr);

extern int accept_tcp_ipv6 (int sk, struct sockaddr_in6 *addr);

extern int bind_tcp_ipv4 (struct sockaddr_in *addr, u_int32_t rwin, u_int32_t wwin);

extern int bind_tcp_ipv6 (struct sockaddr_in6 *addr, u_int32_t rwin, u_int32_t wwin);

extern int connect_tcp_ipv4 (struct sockaddr_in *addr, int nonblock, u_int32_t rwin, u_int32_t wwin);

extern int connect_tcp_ipv6 (struct sockaddr_in6 *addr, int nonblock, u_int32_t rwin, u_int32_t wwin);

extern int iptos_throughput(int socket);

extern int tcp_cork(int socket);

extern int tcp_nodelay(int socket);

extern int tcp_window_clamp(int socket, u_int32_t ww_clamp );

extern int tcp_rcvbuff(int socket, u_int32_t buff_size );

extern int tcp_sndbuff(int socket, u_int32_t buff_size );

extern int tcp_reuseaddr(int socket);

extern int tcp_queue_len(int socket, u_int32_t *qlen);

extern int connection_status (int socket, int *so_error);
