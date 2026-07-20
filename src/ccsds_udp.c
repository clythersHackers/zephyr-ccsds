#include "ccsds_udp.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/__assert.h>
#include <zephyr/sys/util.h>

#ifdef CONFIG_NETWORKING
#include <zephyr/net/socket.h>
#endif

LOG_MODULE_REGISTER(ccsds_udp, CONFIG_AKIRA_LOG_LEVEL);

static K_MUTEX_DEFINE(udp_lock);
static struct ccsds_udp_stats udp_stats;

static void record_error(int error)
{
    if (error == 0) {
        return;
    }

    k_mutex_lock(&udp_lock, K_FOREVER);
    udp_stats.last_error = error;
    k_mutex_unlock(&udp_lock);
}

int ccsds_udp_dispatch_datagram(struct ccsds_profile_input *input,
                                const uint8_t *unit, size_t unit_len)
{
    int ret;

    __ASSERT(input != NULL, "CCSDS UDP input profile is NULL");
    __ASSERT(unit != NULL, "CCSDS UDP input unit is NULL");

    k_mutex_lock(&udp_lock, K_FOREVER);
    udp_stats.datagrams_received++;
    k_mutex_unlock(&udp_lock);

    ret = ccsds_profile_input_dispatch_unit(input, unit, unit_len);
    record_error(ret);

    return ret;
}

#ifdef CONFIG_NETWORKING
#define CCSDS_UDP_THREAD_PRIORITY CONFIG_AKIRA_CCSDS_UDP_THREAD_PRIORITY
#define CCSDS_UDP_THREAD_STACK_SIZE CONFIG_AKIRA_CCSDS_UDP_THREAD_STACK_SIZE

static K_THREAD_STACK_DEFINE(udp_thread_stack, CCSDS_UDP_THREAD_STACK_SIZE);
static struct k_thread udp_thread;
static int udp_rx_fd = -1;
static int udp_tx_fd = -1;
static bool udp_thread_started;
static uint8_t unit_buf[CONFIG_AKIRA_CCSDS_UDP_MAX_UNIT_LEN + 1u];

static void udp_thread_fn(void *p1, void *p2, void *p3)
{
    int fd = (int)(intptr_t)p1;
    struct ccsds_profile_input *input = p2;

    ARG_UNUSED(p3);

    while (true) {
        ssize_t received = zsock_recv(fd, unit_buf, sizeof(unit_buf), 0);

        if (received < 0) {
            int ret = -errno;
            bool running;

            k_mutex_lock(&udp_lock, K_FOREVER);
            running = udp_stats.running;
            udp_stats.last_error = ret;
            k_mutex_unlock(&udp_lock);

            if (!running) {
                break;
            }

            LOG_WRN("udp receive failed ret=%d", ret);
            continue;
        }

        if ((size_t)received > CONFIG_AKIRA_CCSDS_UDP_MAX_UNIT_LEN) {
            k_mutex_lock(&udp_lock, K_FOREVER);
            udp_stats.datagrams_received++;
            udp_stats.last_error = -EMSGSIZE;
            k_mutex_unlock(&udp_lock);
            continue;
        }

        (void)ccsds_udp_dispatch_datagram(input, unit_buf, (size_t)received);
    }

    k_mutex_lock(&udp_lock, K_FOREVER);
    if (udp_rx_fd == fd) {
        (void)zsock_close(fd);
        udp_rx_fd = -1;
    }
    udp_stats.running = false;
    udp_thread_started = false;
    k_mutex_unlock(&udp_lock);
}
#endif /* CONFIG_NETWORKING */

bool ccsds_udp_available(void)
{
#ifdef CONFIG_NETWORKING
    return true;
#else
    return false;
#endif
}

int ccsds_udp_start(struct ccsds_profile_input *input)
{
#ifdef CONFIG_NETWORKING
    struct sockaddr_in local = {
        .sin_family = AF_INET,
        .sin_port = htons(CONFIG_AKIRA_CCSDS_UDP_LOCAL_PORT),
    };
    int fd;
    int ret;

    __ASSERT(input != NULL, "CCSDS UDP input profile is NULL");

    ret = zsock_inet_pton(AF_INET, CONFIG_AKIRA_CCSDS_UDP_LOCAL_IP,
                          &local.sin_addr);
    if (ret != 1) {
        return -EINVAL;
    }

    k_mutex_lock(&udp_lock, K_FOREVER);
    if (udp_stats.running || udp_thread_started) {
        k_mutex_unlock(&udp_lock);
        return -EALREADY;
    }
    k_mutex_unlock(&udp_lock);

    fd = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        return -errno;
    }

    ret = zsock_bind(fd, (const struct sockaddr *)&local, sizeof(local));
    if (ret < 0) {
        ret = -errno;
        (void)zsock_close(fd);
        return ret;
    }

    k_mutex_lock(&udp_lock, K_FOREVER);
    memset(&udp_stats, 0, sizeof(udp_stats));
    udp_stats.running = true;
    udp_rx_fd = fd;
    udp_thread_started = true;
    k_mutex_unlock(&udp_lock);

    k_thread_create(&udp_thread, udp_thread_stack,
                    K_THREAD_STACK_SIZEOF(udp_thread_stack), udp_thread_fn,
                    (void *)(intptr_t)fd, input, NULL, CCSDS_UDP_THREAD_PRIORITY,
                    0, K_NO_WAIT);
    k_thread_name_set(&udp_thread, "ccsds_udp");

    LOG_INF("udp input listening on %s:%u", CONFIG_AKIRA_CCSDS_UDP_LOCAL_IP,
            CONFIG_AKIRA_CCSDS_UDP_LOCAL_PORT);

    return 0;
#else
    ARG_UNUSED(input);
    return -ENOTSUP;
#endif
}

void ccsds_udp_stop(void)
{
#ifdef CONFIG_NETWORKING
    int fd;

    k_mutex_lock(&udp_lock, K_FOREVER);
    udp_stats.running = false;
    fd = udp_rx_fd;
    udp_rx_fd = -1;
    k_mutex_unlock(&udp_lock);

    if (fd >= 0) {
        (void)zsock_close(fd);
    }
#endif
}

int ccsds_udp_send(void *user, const uint8_t *unit, size_t unit_len)
{
#ifdef CONFIG_NETWORKING
    struct sockaddr_in peer = {
        .sin_family = AF_INET,
        .sin_port = htons(CONFIG_AKIRA_CCSDS_UDP_PEER_PORT),
    };
    ssize_t sent;
    int ret;

    ARG_UNUSED(user);
    __ASSERT(unit != NULL, "CCSDS UDP output unit is NULL");

    if (unit_len == 0u ||
        unit_len > CONFIG_AKIRA_CCSDS_UDP_MAX_UNIT_LEN) {
        record_error(-EMSGSIZE);
        return -EMSGSIZE;
    }

    ret = zsock_inet_pton(AF_INET, CONFIG_AKIRA_CCSDS_UDP_PEER_IP,
                          &peer.sin_addr);
    if (ret != 1) {
        record_error(-EINVAL);
        return -EINVAL;
    }

    k_mutex_lock(&udp_lock, K_FOREVER);
    if (udp_tx_fd < 0) {
        udp_tx_fd = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (udp_tx_fd < 0) {
            ret = -errno;
            udp_stats.last_error = ret;
            k_mutex_unlock(&udp_lock);
            return ret;
        }
    }

    sent = zsock_sendto(udp_tx_fd, unit, unit_len, 0,
                        (const struct sockaddr *)&peer, sizeof(peer));
    if (sent < 0) {
        ret = -errno;
        udp_stats.last_error = ret;
        k_mutex_unlock(&udp_lock);
        return ret;
    }
    if (sent != (ssize_t)unit_len) {
        udp_stats.last_error = -EIO;
        k_mutex_unlock(&udp_lock);
        return -EIO;
    }

    udp_stats.datagrams_sent++;
    k_mutex_unlock(&udp_lock);
    return 0;
#else
    ARG_UNUSED(user);
    ARG_UNUSED(unit);
    ARG_UNUSED(unit_len);
    return -ENOTSUP;
#endif
}

void ccsds_udp_get_stats(struct ccsds_udp_stats *stats)
{
    __ASSERT(stats != NULL, "CCSDS UDP stats output is NULL");

    k_mutex_lock(&udp_lock, K_FOREVER);
    *stats = udp_stats;
    k_mutex_unlock(&udp_lock);
}
