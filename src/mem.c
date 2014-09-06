#include <stdio.h>
#include <stdlib.h>
#include "mem_types.h"
#include "socks5.h"


struct tcp_socket *
dequeue_tcp_socket(struct tcp_socket_queue *queue)
{
    struct tcp_socket *ptr;
    
    ptr = queue->head;
    if (ptr != NULL_TCP_SOCKET)
    {	
	queue->head = ptr->next;
	ptr->next= NULL_TCP_SOCKET;
	if (queue->head == NULL_TCP_SOCKET)
	{
	    queue->tail = NULL_TCP_SOCKET;	    
	}
    }
    return ptr;
}

void
enqueue_tcp_socket(struct tcp_socket_queue *queue, struct tcp_socket *ptr)
{
    ptr->next = NULL;
    if (queue->tail == NULL && queue->head == NULL)
	queue->head = ptr;
    else
	queue->tail->next = ptr;
    queue->tail = ptr;	
}


void 
enqueue_rdy_send(struct tcp_socket_queue *queue, struct tcp_socket *ptr)
{
    ptr->nextready_send = NULL;
    if (queue->tail == NULL && queue->head == NULL)
        queue->head = ptr;
    else
        queue->tail->nextready_send = ptr;    
    queue->tail = ptr;
}

void 
enqueue_rdy_recv(struct tcp_socket_queue *queue, struct tcp_socket *ptr)
{
    ptr->nextready_recv = NULL;
    if (queue->tail == NULL && queue->head == NULL)
        queue->head = ptr;
    else
        queue->tail->nextready_recv = ptr;    
    queue->tail = ptr;
}

void
enqueue_pending_msg(struct msgbuff_queue *queue, struct msgbuff *ptr)
{
    ptr->next = NULL;
    if (queue->tail == NULL && queue->head == NULL)
	queue->head = ptr;
    else
	queue->tail->next = ptr;
    queue->tail = ptr;
}

void 
push_pending_msg(struct msgbuff_queue *queue, struct msgbuff *ptr)
{
    ptr->next = queue->head;
    queue->head = ptr;
    if (queue->tail == NULL)
	queue->tail = ptr;
}

int 
queue_filled(struct msgbuff_queue *queue)
{
    if ( queue->head != NULL )
    {
	return 1;
    }
    return 0;
}


struct msgbuff *
dequeue_pending_msg(struct msgbuff_queue *queue) 
{
    struct msgbuff *ptr;

    ptr = queue->head;
    if (ptr != NULL)
    {
	queue->head = ptr->next;
	if (queue->head == NULL)
	{
	    queue->tail = NULL;
	}
    }
    return ptr;
}

struct tcp_socket *
dequeue_rdy_recv(struct tcp_socket_queue *queue)
{
    struct tcp_socket *ptr;
    
    ptr = queue->head;
    if (ptr != NULL_TCP_SOCKET)
    {	
	queue->head = ptr->nextready_recv;
	ptr->nextready_recv = NULL_TCP_SOCKET;
	if (queue->head == NULL_TCP_SOCKET)
	{
	    queue->tail = NULL_TCP_SOCKET;	    
	}
    }
    return ptr;
}

struct tcp_socket *
dequeue_rdy_send(struct tcp_socket_queue *queue)
{
    struct tcp_socket *ptr;
    
    ptr = queue->head;
    if (ptr != NULL_TCP_SOCKET)
    {	
	queue->head = ptr->nextready_send;
	ptr->nextready_send = NULL_TCP_SOCKET;
	if (queue->head == NULL_TCP_SOCKET)
	{
	    queue->tail = NULL_TCP_SOCKET;	    
	}
    }
    return ptr;
}


/*
 * Crea la estructura tcp_socket y la inicializa
 */
struct tcp_socket *
alloc_tcp_socket(void)
{
    struct tcp_socket *new_ptr;
    new_ptr = calloc(sizeof(struct tcp_socket),1);
    if (new_ptr != NULL_TCP_SOCKET) 
    {
	new_ptr->state      		= NEW;
	new_ptr->kind       		= SOCKET_UNUSED;
	new_ptr->socket     		= -1;
	new_ptr->msgq.head 		= NULL;
	new_ptr->msgq.tail 		= NULL;
	new_ptr->peer	    		= NULL_TCP_SOCKET;
	new_ptr->next	    		= NULL_TCP_SOCKET;
	new_ptr->nextready_send 	= NULL_TCP_SOCKET;
	new_ptr->nextready_recv 	= NULL_TCP_SOCKET;
    }
    return new_ptr;
}


void
free_tcp_socket (struct tcp_socket *sk)
{
    if (sk != NULL_TCP_SOCKET)
    {
	free(sk);
    }
}


struct msgbuff *
alloc_msg_buffer(size_t len)
{
    struct msgbuff *new_ptr;
    
    new_ptr = calloc(sizeof(struct msgbuff), 1);
    if ( new_ptr != NULL ) 
    {
	new_ptr->buffer = calloc(1, len);
	if ( new_ptr->buffer == NULL )
	{
	    free(new_ptr);
	    new_ptr = NULL;
	}
	new_ptr->offset  = 0;
	new_ptr->nrbytes = len;
	new_ptr->next    = NULL;
    }
    return new_ptr;
}

void
free_msg_buffer (struct msgbuff *msg)
{
    if (msg != NULL)
    {
	if (msg->buffer != NULL)
	{
	    free(msg->buffer);
	}
	free(msg);
    }
    return;
}    


void dump_queue(FILE *f, const char *str, struct tcp_socket_queue *q, u_int8_t queue_type)
{
    struct tcp_socket *sk;
    int i = 0;
    
    sk = q->head;
    while (sk != NULL)
    {
	fprintf(f, "h: %#x | t: %#x {%s} - %d[%#x] - State: %d - Kind: %d - Socket: %d - Next: %#x - Peer: %#x - Queue: %d\n", q->head, 
															       q->tail,
															       str,
															       i, 
															       sk, 
															       sk->state, 
															       sk->kind, 
															       sk->socket, 
															       sk->next, 
															       sk->peer, 
															       (sk->msgq).head);
	if (queue_type == ALL_TCP_SOCKETS)
	{
	    sk = sk->next;
	}
	if (queue_type == RECV_READY)
	{
	    sk = sk->nextready_recv;
	}
	if (queue_type == SEND_READY)
	{
	    sk = sk->nextready_send;
	}    
	i++;
    }	
    return;
}    


