#ifndef _MEM_TYPES_H
#define _MEM_TYPES_H 1

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

struct msgbuff {
    size_t offset;
    size_t nrbytes;
    
    void *buffer;
    struct msgbuff *next;
};

struct msgbuff_queue {
    struct msgbuff *head;
    struct msgbuff *tail;
};


struct tcp_socket {
    u_int8_t  state;				/* Estado 		   */
    u_int8_t  kind;				/* Tipo de socket 	   */
#define SOCKET_SERVER 0x00			/* Socket Server Principal */
#define SOCKET_PASV   0x01			/* Socket que espera conexion: Request: BIND */
#define SOCKET_PEER   0x02			/* Socket Par */
#define SOCKET_UNUSED 0xFF
    u_int16_t family;				/* IPV4 o IPV6 */
    int	      socket;				/* Canal de comunicacion */

    struct msgbuff_queue msgq;

    struct tcp_socket *peer;
    struct tcp_socket *next;
    struct tcp_socket *nextready_send;
    struct tcp_socket *nextready_recv;
};    


#define NULL_TCP_SOCKET (struct tcp_socket *) 0        

struct tcp_socket_queue {
    struct tcp_socket *head;
    struct tcp_socket *tail;
};        

#define ALL_TCP_SOCKETS 0
#define SEND_READY	1
#define RECV_READY	2



#endif
