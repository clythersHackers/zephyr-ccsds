/**
 * @file ccsds_tm_frame.h
 * @brief CCSDS TM transfer frame packet admission boundary.
 */

#ifndef AKIRA_CCSDS_TM_FRAME_H
#define AKIRA_CCSDS_TM_FRAME_H

#include "ccsds_types.h"

#include <zephyr/kernel.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t ccsds_tm_route_mask_t;

#define CCSDS_TM_ROUTE_NONE        ((ccsds_tm_route_mask_t)0u)
#define CCSDS_TM_ROUTE_LOG         ((ccsds_tm_route_mask_t)BIT(0))
#define CCSDS_TM_ROUTE_ARCHIVE     ((ccsds_tm_route_mask_t)BIT(1))
#define CCSDS_TM_ROUTE_UART        ((ccsds_tm_route_mask_t)BIT(2))
#define CCSDS_TM_ROUTE_UDP         ((ccsds_tm_route_mask_t)BIT(3))
#define CCSDS_TM_ROUTE_CAN         ((ccsds_tm_route_mask_t)BIT(4))
#define CCSDS_TM_ROUTE_LOW_RATE    ((ccsds_tm_route_mask_t)BIT(16))
#define CCSDS_TM_ROUTE_MEDIUM_RATE ((ccsds_tm_route_mask_t)BIT(17))
#define CCSDS_TM_ROUTE_HIGH_RATE   ((ccsds_tm_route_mask_t)BIT(18))

// define combined masks for validity checking and route registration
#define CCSDS_TM_LOCAL_ROUTE_MASK    ((ccsds_tm_route_mask_t)GENMASK(4, 0))
#define CCSDS_TM_DOWNLINK_ROUTE_MASK ((ccsds_tm_route_mask_t)GENMASK(18, 16))
#define CCSDS_TM_SUPPORTED_ROUTE_MASK                                      \
    (CCSDS_TM_LOCAL_ROUTE_MASK | CCSDS_TM_DOWNLINK_ROUTE_MASK)

/**
 * @brief Deliver one encoded TM transfer frame to a route implementation.
 *
 * @param vcid Virtual channel ID that produced the frame.
 * @param frame Encoded transfer frame or CADU bytes.
 * @param frame_len Length of @p frame in bytes.
 * @param user_data Opaque pointer registered with the route.
 *
 * @return 0 on success, or a negative errno from the route implementation.
 */
typedef int (*ccsds_tm_route_fn_t)(uint8_t vcid, const uint8_t *frame,
                                   size_t frame_len, void *user_data);

/**
 * @brief Initialize TM frame admission state and routing tables.
 *
 * This must be called before any other TM frame API. It resets VC pipe state,
 * frame counters, route registrations, and per-VC route masks.
 *
 * @return 0 on success.
 */
int ccsds_tm_frame_init(void);

/**
 * @brief Register a callback for one TM route bit.
 *
 * @param route_bit Exactly one supported nonzero CCSDS_TM_ROUTE_* bit.
 * @param fn Callback invoked for frames routed through @p route_bit.
 * @param user_data Opaque pointer passed to @p fn.
 *
 * @return 0 on success, or -EINVAL for an invalid route bit or NULL callback.
 */
int ccsds_tm_frame_register_route(ccsds_tm_route_mask_t route_bit,
                                  ccsds_tm_route_fn_t fn, void *user_data);

/**
 * @brief Set the route mask used by a virtual channel.
 *
 * @param vcid Virtual channel ID, 0 through 7.
 * @param route_mask Supported route bits, or CCSDS_TM_ROUTE_NONE.
 *
 * @return 0 on success, or -EINVAL for an invalid VCID or unsupported route bit.
 */
int ccsds_tm_frame_set_vc_route(uint8_t vcid,
                                ccsds_tm_route_mask_t route_mask);

/**
 * @brief Read the route mask currently used by a virtual channel.
 *
 * @param vcid Virtual channel ID, 0 through 7.
 * @param route_mask Output pointer for the current VC route mask.
 *
 * @return 0 on success, or -EINVAL for an invalid VCID or NULL output pointer.
 */
int ccsds_tm_frame_get_vc_route(uint8_t vcid,
                                ccsds_tm_route_mask_t *route_mask);

/**
 * @brief Start the internal TM frame generator service.
 *
 * This schedules the generator immediately. Follow-up generator cycles use
 * @p active_delay after queued packet data is observed, or @p idle_delay when
 * all VC queues are idle. This slice does not build TM frames yet.
 *
 * @param active_delay Delay after a packet-bearing generator cycle.
 * @param idle_delay Delay after an idle generator cycle.
 *
 * @return 0 on success.
 */
int ccsds_tm_frame_start(k_timeout_t active_delay, k_timeout_t idle_delay);

/**
 * @brief Stop the internal TM frame generator service.
 *
 * @return 0 on success.
 */
int ccsds_tm_frame_stop(void);

/**
 * @brief Admit one complete encoded CCSDS Space Packet into a VC queue.
 *
 * @param vcid Virtual channel ID, 0 through 7.
 * @param packet Complete encoded CCSDS Space Packet.
 * @param packet_len Length of @p packet in bytes.
 * @param timeout Timeout used for the VC write mutex and pipe writes.
 *
 * @return 0 on success, -EINVAL for invalid packet/VC input, -EMSGSIZE if the
 *         packet cannot fit in the VC queue, or a Zephyr mutex/pipe error.
 */
int ccsds_tm_frame_add(uint8_t vcid, const uint8_t *packet, size_t packet_len,
                       k_timeout_t timeout);

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_TM_FRAME_H */
