#include "ccsds_udp.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/logging/log.h>
#include <zephyr/sys/__assert.h>
#include <zephyr/sys/util.h>

#ifdef CONFIG_NETWORKING
#include <zephyr/net/socket.h>
#endif

LOG_MODULE_REGISTER(ccsds_udp);

static void record_error(struct ccsds_udp *udp, int error)
{
    if (error == 0) {
        return;
    }

    k_mutex_lock(&udp->lock, K_FOREVER);
    udp->stats.last_error = error;
    k_mutex_unlock(&udp->lock);
}

int ccsds_udp_dispatch_datagram(struct ccsds_udp *udp, const uint8_t *unit,
                                size_t unit_len)
{
    int ret;

    __ASSERT(udp != NULL, "CCSDS UDP instance is NULL");
    __ASSERT(udp->initialized, "CCSDS UDP instance is not initialized");
    __ASSERT(unit != NULL, "CCSDS UDP input unit is NULL");

    if (unit_len == 0u || unit_len > udp->config.max_unit_len) {
        record_error(udp, -EMSGSIZE);
        return -EMSGSIZE;
    }

    k_mutex_lock(&udp->lock, K_FOREVER);
    udp->stats.datagrams_received++;
    k_mutex_unlock(&udp->lock);

    ret = udp->config.receive(udp->config.receive_user, unit, unit_len);
    record_error(udp, ret);
    return ret;
}

#ifdef CONFIG_NETWORKING
static void udp_thread_fn(void *p1, void *p2, void *p3)
{
    struct ccsds_udp *udp = p1;
    int fd = (int)(intptr_t)p2;

    ARG_UNUSED(p3);

    while (true) {
        ssize_t received =
            zsock_recv(fd, udp->unit_buf, udp->config.max_unit_len + 1u, 0);

        if (received < 0) {
            int ret = -errno;
            bool running;

            k_mutex_lock(&udp->lock, K_FOREVER);
            running = udp->stats.running;
            udp->stats.last_error = ret;
            k_mutex_unlock(&udp->lock);

            if (!running) {
                break;
            }
            LOG_WRN("udp receive failed ret=%d", ret);
            continue;
        }

        if ((size_t)received > udp->config.max_unit_len) {
            record_error(udp, -EMSGSIZE);
            continue;
        }

        (void)ccsds_udp_dispatch_datagram(udp, udp->unit_buf,
                                          (size_t)received);
    }

    k_mutex_lock(&udp->lock, K_FOREVER);
    if (udp->rx_fd == fd) {
        (void)zsock_close(fd);
        udp->rx_fd = -1;
    }
    udp->stats.running = false;
    udp->thread_started = false;
    k_mutex_unlock(&udp->lock);
}
#endif

bool ccsds_udp_available(void)
{
#ifdef CONFIG_NETWORKING
    return true;
#else
    return false;
#endif
}

int ccsds_udp_init(struct ccsds_udp *udp,
                   const struct ccsds_udp_config *config)
{
    __ASSERT(udp != NULL, "CCSDS UDP instance is NULL");
    __ASSERT(config != NULL, "CCSDS UDP configuration is NULL");
    __ASSERT(config->receive != NULL, "CCSDS UDP receive callback is NULL");

    if (config->local_ip == NULL || config->peer_ip == NULL ||
        config->local_port == 0u || config->peer_port == 0u ||
        config->max_unit_len == 0u ||
        config->max_unit_len > CONFIG_CCSDS_UDP_MAX_UNIT_LEN) {
        return -EINVAL;
    }

    memset(udp, 0, sizeof(*udp));
    udp->config = *config;
    udp->rx_fd = -1;
    udp->tx_fd = -1;
    k_mutex_init(&udp->lock);
    udp->initialized = true;
    return 0;
}

int ccsds_udp_start(struct ccsds_udp *udp)
{
#ifdef CONFIG_NETWORKING
    struct sockaddr_in local = {
        .sin_family = AF_INET,
        .sin_port = htons(udp->config.local_port),
    };
    int fd;
    int ret;

    __ASSERT(udp != NULL, "CCSDS UDP instance is NULL");
    __ASSERT(udp->initialized, "CCSDS UDP instance is not initialized");

    ret = zsock_inet_pton(AF_INET, udp->config.local_ip, &local.sin_addr);
    if (ret != 1) {
        return -EINVAL;
    }

    k_mutex_lock(&udp->lock, K_FOREVER);
    if (udp->stats.running || udp->thread_started) {
        k_mutex_unlock(&udp->lock);
        return -EALREADY;
    }
    k_mutex_unlock(&udp->lock);

    fd = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        return -errno;
    }
    if (zsock_bind(fd, (const struct sockaddr *)&local, sizeof(local)) < 0) {
        ret = -errno;
        (void)zsock_close(fd);
        return ret;
    }

    k_mutex_lock(&udp->lock, K_FOREVER);
    memset(&udp->stats, 0, sizeof(udp->stats));
    udp->stats.running = true;
    udp->rx_fd = fd;
    udp->thread_started = true;
    k_mutex_unlock(&udp->lock);

    k_thread_create(&udp->thread, udp->thread_stack,
                    K_KERNEL_STACK_SIZEOF(udp->thread_stack), udp_thread_fn,
                    udp, (void *)(intptr_t)fd, NULL,
                    udp->config.thread_priority, 0, K_NO_WAIT);
    if (udp->config.thread_name != NULL) {
        (void)k_thread_name_set(&udp->thread, udp->config.thread_name);
    }

    LOG_INF("udp input listening on %s:%u", udp->config.local_ip,
            udp->config.local_port);
    return 0;
#else
    ARG_UNUSED(udp);
    return -ENOTSUP;
#endif
}

void ccsds_udp_stop(struct ccsds_udp *udp)
{
    __ASSERT(udp != NULL, "CCSDS UDP instance is NULL");
    __ASSERT(udp->initialized, "CCSDS UDP instance is not initialized");

#ifdef CONFIG_NETWORKING
    int rx_fd;
    int tx_fd;

    k_mutex_lock(&udp->lock, K_FOREVER);
    udp->stats.running = false;
    rx_fd = udp->rx_fd;
    tx_fd = udp->tx_fd;
    udp->rx_fd = -1;
    udp->tx_fd = -1;
    k_mutex_unlock(&udp->lock);

    if (rx_fd >= 0) {
        (void)zsock_close(rx_fd);
    }
    if (tx_fd >= 0) {
        (void)zsock_close(tx_fd);
    }
#endif
}

int ccsds_udp_send(void *user, const uint8_t *unit, size_t unit_len)
{
    struct ccsds_udp *udp = user;

    __ASSERT(udp != NULL, "CCSDS UDP instance is NULL");
    __ASSERT(udp->initialized, "CCSDS UDP instance is not initialized");
    __ASSERT(unit != NULL, "CCSDS UDP output unit is NULL");

#ifdef CONFIG_NETWORKING
    struct sockaddr_in peer = {
        .sin_family = AF_INET,
        .sin_port = htons(udp->config.peer_port),
    };
    ssize_t sent;
    int ret;

    if (unit_len == 0u || unit_len > udp->config.max_unit_len) {
        record_error(udp, -EMSGSIZE);
        return -EMSGSIZE;
    }

    ret = zsock_inet_pton(AF_INET, udp->config.peer_ip, &peer.sin_addr);
    if (ret != 1) {
        record_error(udp, -EINVAL);
        return -EINVAL;
    }

    k_mutex_lock(&udp->lock, K_FOREVER);
    if (udp->tx_fd < 0) {
        udp->tx_fd = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (udp->tx_fd < 0) {
            ret = -errno;
            udp->stats.last_error = ret;
            k_mutex_unlock(&udp->lock);
            return ret;
        }
    }

    sent = zsock_sendto(udp->tx_fd, unit, unit_len, 0,
                        (const struct sockaddr *)&peer, sizeof(peer));
    if (sent < 0) {
        ret = -errno;
        udp->stats.last_error = ret;
        k_mutex_unlock(&udp->lock);
        return ret;
    }
    if (sent != (ssize_t)unit_len) {
        udp->stats.last_error = -EIO;
        k_mutex_unlock(&udp->lock);
        return -EIO;
    }

    udp->stats.datagrams_sent++;
    k_mutex_unlock(&udp->lock);
    return 0;
#else
    ARG_UNUSED(udp);
    ARG_UNUSED(unit_len);
    return -ENOTSUP;
#endif
}

void ccsds_udp_get_stats(struct ccsds_udp *udp,
                         struct ccsds_udp_stats *stats)
{
    __ASSERT(udp != NULL, "CCSDS UDP instance is NULL");
    __ASSERT(udp->initialized, "CCSDS UDP instance is not initialized");
    __ASSERT(stats != NULL, "CCSDS UDP stats output is NULL");

    k_mutex_lock(&udp->lock, K_FOREVER);
    *stats = udp->stats;
    k_mutex_unlock(&udp->lock);
}
