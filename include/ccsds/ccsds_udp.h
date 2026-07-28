/**
 * @file ccsds_udp.h
 * @brief Instance-based UDP adapter for bounded protocol units.
 */

#ifndef CCSDS_UDP_H
#define CCSDS_UDP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*ccsds_udp_receive_cb_t)(void *user, const uint8_t *unit,
                                     size_t unit_len);

struct ccsds_udp_config {
    const char *local_ip;
    uint16_t local_port;
    const char *peer_ip;
    uint16_t peer_port;
    size_t max_unit_len;
    int thread_priority;
    const char *thread_name;
    ccsds_udp_receive_cb_t receive;
    void *receive_user;
};

struct ccsds_udp_stats {
    bool running;
    uint32_t datagrams_received;
    uint32_t datagrams_sent;
    int last_error;
};

/**
 * Caller-owned UDP adapter. Each instance owns its sockets, counters, receive
 * workspace, thread, stack, and lock.
 */
struct ccsds_udp {
    struct ccsds_udp_config config;
    struct k_mutex lock;
    struct k_thread thread;
    K_KERNEL_STACK_MEMBER(thread_stack,
                          CONFIG_CCSDS_UDP_THREAD_STACK_SIZE);
    uint8_t unit_buf[CONFIG_CCSDS_UDP_MAX_UNIT_LEN + 1u];
    struct ccsds_udp_stats stats;
    int rx_fd;
    int tx_fd;
    bool thread_started;
    bool initialized;
};

bool ccsds_udp_available(void);

int ccsds_udp_init(struct ccsds_udp *udp,
                   const struct ccsds_udp_config *config);

int ccsds_udp_start(struct ccsds_udp *udp);

void ccsds_udp_stop(struct ccsds_udp *udp);

int ccsds_udp_send(void *user, const uint8_t *unit, size_t unit_len);

void ccsds_udp_get_stats(struct ccsds_udp *udp,
                         struct ccsds_udp_stats *stats);

int ccsds_udp_dispatch_datagram(struct ccsds_udp *udp, const uint8_t *unit,
                                size_t unit_len);

#ifdef __cplusplus
}
#endif

#endif /* CCSDS_UDP_H */
