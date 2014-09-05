#ifndef _SOCKS5_H
#define _SOCKS5_H

#define SUCCESS   0x00  /* succeeded 			     */
#define SFAILURE  0x01  /* general SOCKS server failure      */
#define CNOTALL   0x02  /* connection not allowed by ruleset */
#define NUNREACHE 0x03  /* Network unreachable               */
#define HUNREACHE 0x04  /* Host unreachable                  */
#define CREFUSED  0x05  /* Connection refused                */
#define CNOTSUPP  0x07  /* Command not supported             */
#define ANOTSUPP  0x08  /* Address type not supported	     */


#define SOCKS5_PORT 1080

#define NO_AUTH   0x00
#define GSSAPI    0x01
#define USERPASS  0x02
#define NOTACCEPT 0xFF


#define CONNECT		0x01
#define BIND		0x02	
#define UDPASSOCIATE	0x03

#define IPV4ADDR	0x01
#define IPV6ADDR	0x04
#define DOMAINNAME	0x03


#define NEW			0xFF
#define WAITING_METHODS		0x00
#define PENDING_SND_METHOD	0x08
#define PENDING_SND_REPLY	0x09
#define CONNECTING		0x10
#define WAITING_USERPASS	0x05
#define WAITING_REQUEST		0x01
#define WAITING_PEER		0x02
#define WAITING_CONNECTION	0x06
#define PIPELINE		0x03
#define WAITING_CLOSE		0x04	/* Solamente puede escribir - Lectura no esta permitido */
#define CLOSE			0x07

#include <sys/types.h>
#include <netinet/in.h>

struct socks_hdr {
    u_int8_t ver;
    union {
	u_int8_t cmd;
	u_int8_t rep;
    } kind;
    u_int8_t rsv;
    u_int8_t atyp;
};

struct socks_auth {
    u_int8_t   ver;
    union {
	u_int8_t method;
	u_int8_t nmethod;
    } md;
};


struct sockname {
    u_int16_t family;
    union {
	struct in_addr  addr4;
	struct in6_addr addr6;
    } in;
    u_int16_t port;
};


#define WREQUEST_BUFFER 262
#define WMETHODS_BUFFER 257
#define SZS5AUTH sizeof(struct socks_auth)
#define SZS5HDR  sizeof(struct socks_hdr)

#endif

