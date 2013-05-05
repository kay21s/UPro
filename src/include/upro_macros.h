#ifndef UPRO_MACROS_H
#define UPRO_MACROS_H

#include <stdlib.h>

/* Boolean */
#define UPRO_FALSE 0
#define UPRO_TRUE  !UPRO_FALSE
#define UPRO_ERROR -1

/* Architecture */
#define INTSIZE sizeof(int)

/* Print macros */
#define UPRO_INFO     0x1000
#define UPRO_ERR      0X1001
#define UPRO_WARN     0x1002
#define UPRO_BUG      0x1003


//#define upro_info(...)  upro_print(UPRO_INFO, __VA_ARGS__)
//#define upro_err(...)   upro_print(UPRO_ERR, __VA_ARGS__)
//#define upro_warn(...)  upro_print(UPRO_WARN, __VA_ARGS__)
//#define upro_trace(...)  upro_print(UPRO_WARN, __VA_ARGS__)
#define upro_info  printf
#define upro_err   printf
#define upro_warn  printf
#define upro_trace  printf

/* Transport type */
#ifndef ARRAY_SIZE
# define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#ifdef __GNUC__ /* GCC supports this since 2.3. */
 #define PRINTF_WARNINGS(a,b) __attribute__ ((format (printf, a, b)))
#else
 #define PRINTF_WARNINGS(a,b)
#endif

#ifdef __GNUC__ /* GCC supports this since 2.7. */
 #define UNUSED_PARAM __attribute__ ((unused))
#else
 #define UNUSED_PARAM
#endif

/*
 * Validation macros
 * -----------------
 * Based on article http://lwn.net/Articles/13183/
 *
 * ---
 * ChangeSet 1.803, 2002/10/18 16:28:57-07:00, torvalds@home.transmeta.com
 *
 *	Make a polite version of BUG_ON() - WARN_ON() which doesn't
 *	kill the machine.
 *
 *	Damn I hate people who kill the machine for no good reason.
 * ---
 *
 */

#define upro_unlikely(x) __builtin_expect((x),0)
#define upro_likely(x) __builtin_expect((x),1)
#define upro_prefetch(x, ...) __builtin_prefetch(x, __VA_ARGS__)

#define upro_is_bool(x) ((x == UPRO_TRUE || x == UPRO_FALSE) ? 1 : 0)

#define upro_bug(condition) do {                                          \
        if (upro_unlikely((condition)!=0)) {                              \
            upro_print(UPRO_BUG, "Bug found in %s() at %s:%d",              \
                     __FUNCTION__, __FILE__, __LINE__);                 \
            abort();                                                    \
        }                                                               \
    } while(0)

/*
 * Macros to calculate sub-net data using ip address and sub-net prefix
 */

#define UPRO_NET_IP_OCTECT(addr,pos) (addr >> (8 * pos) & 255)
#define UPRO_NET_NETMASK(addr,net) htonl((0xffffffff << (32 - net)))
#define UPRO_NET_BROADCAST(addr,net) (addr | ~UPRO_NET_NETMASK(addr,net))
#define UPRO_NET_NETWORK(addr,net) (addr & UPRO_NET_NETMASK(addr,net))
#define UPRO_NET_WILDCARD(addr,net) (UPRO_NET_BROADCAST(addr,net) ^ UPRO_NET_NETWORK(addr,net))
#define UPRO_NET_HOSTMIN(addr,net) net == 31 ? UPRO_NET_NETWORK(addr,net) : (UPRO_NET_NETWORK(addr,net) + 0x01000000)
#define UPRO_NET_HOSTMAX(addr,net) net == 31 ? UPRO_NET_BROADCAST(addr,net) : (UPRO_NET_BROADCAST(addr,net) - 0x01000000);

#if __GNUC__ >= 4
 #define UPRO_EXPORT __attribute__ ((visibility ("default")))
#else
 #define UPRO_EXPORT
#endif

// TRACE
#define UPRO_TRACE(...) do {} while (0)

#endif
