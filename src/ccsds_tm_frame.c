#include "ccsds_tm_frame.h"

#include <errno.h>
#include <string.h>

#include <zephyr/sys/util.h>

#define CCSDS_TM_MAX_VC_ID 7u
#define CCSDS_TM_VC_COUNT (CCSDS_TM_MAX_VC_ID + 1u)
#define CCSDS_SPACE_PACKET_MIN_LEN (CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN + 1u)

struct ccsds_tm_vc {
    struct k_mutex write_lock;
    struct k_pipe pending;
    uint8_t pending_storage[CONFIG_AKIRA_CCSDS_TM_QUEUE_DEPTH];

    uint16_t packet_rem;
    bool packet_is_idle;

    uint8_t vcfc;
};

static struct ccsds_tm_vc vcs[CCSDS_TM_VC_COUNT];
static uint8_t frame_buf[CONFIG_AKIRA_CCSDS_MAX_FRAME_LEN];
static uint8_t mcfc;
static bool initialized;

static size_t packet_total_len(const uint8_t *packet)
{
    uint16_t length_field = ((uint16_t)packet[4] << 8) | packet[5];

    return CCSDS_SPACE_PACKET_PRIMARY_HDR_LEN + (size_t)length_field + 1u;
}

int ccsds_tm_frame_init(void)
{
    for (size_t i = 0u; i < ARRAY_SIZE(vcs); i++) {
        vcs[i].packet_rem = 0u;
        vcs[i].packet_is_idle = false;
        vcs[i].vcfc = 0u;

        k_mutex_init(&vcs[i].write_lock);
        k_pipe_init(&vcs[i].pending, vcs[i].pending_storage,
                    sizeof(vcs[i].pending_storage));
    }

    memset(frame_buf, 0, sizeof(frame_buf));
    mcfc = 0u;
    initialized = true;

    return 0;
}

int ccsds_tm_frame_add(uint8_t vcid, const uint8_t *packet, size_t packet_len,
                       k_timeout_t timeout)
{
    struct ccsds_tm_vc *vc;
    size_t written = 0u;
    int ret;

    if (!packet || packet_len < CCSDS_SPACE_PACKET_MIN_LEN) {
        return -EINVAL;
    }

    if (packet_total_len(packet) != packet_len) {
        return -EINVAL;
    }

    if (packet_len > CONFIG_AKIRA_CCSDS_TM_QUEUE_DEPTH) {
        return -EMSGSIZE;
    }

    if (vcid > CCSDS_TM_MAX_VC_ID) {
        return -EINVAL;
    }

    __ASSERT(initialized, "ccsds_tm_frame_init() not called");

    vc = &vcs[vcid];

    ret = k_mutex_lock(&vc->write_lock, timeout);
    if (ret != 0) {
        return ret;
    }

    while (written < packet_len) {
        ret = k_pipe_write(&vc->pending, &packet[written],
                           packet_len - written, timeout);
        if (ret < 0) {
            goto out_unlock;
        }
        __ASSERT(ret > 0, "k_pipe_write() made no progress");
        if (ret == 0) {
            ret = -EIO;
            goto out_unlock;
        }

        written += (size_t)ret;
    }

    ret = 0;

out_unlock:
    k_mutex_unlock(&vc->write_lock);

    return ret;
}
