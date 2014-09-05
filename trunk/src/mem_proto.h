#include "mem_types.h"


extern struct tcp_socket *dequeue_tcp_socket(struct tcp_socket_queue *queue);

extern void enqueue_tcp_socket(struct tcp_socket_queue *queue, struct tcp_socket *ptr);

extern void enqueue_rdy_send(struct tcp_socket_queue *queue, struct tcp_socket *ptr);

extern void enqueue_rdy_recv(struct tcp_socket_queue *queue, struct tcp_socket *ptr);

extern void enqueue_pending_msg(struct msgbuff_queue *queue, struct msgbuff *ptr);

extern void push_pending_msg(struct msgbuff_queue *queue, struct msgbuff *ptr);

extern struct msgbuff *dequeue_pending_msg(struct msgbuff_queue *queue);

extern struct tcp_socket *dequeue_rdy_recv(struct tcp_socket_queue *queue);

extern struct tcp_socket *dequeue_rdy_send(struct tcp_socket_queue *queue);

extern struct tcp_socket *alloc_tcp_socket(void);

extern void free_tcp_socket (struct tcp_socket *sk);

extern struct msgbuff *alloc_msg_buffer(size_t len);

extern void free_msg_buffer (struct msgbuff *msg);

extern void clean_tcp_sockets ( struct tcp_socket_queue *q );

extern int queue_filled(struct msgbuff_queue *q);

extern void dump_queue(FILE *f, const char *str, struct tcp_socket_queue *q, u_int8_t queue_type);