/**
 * @file ccsds_udp.h
 * @brief UDP transport for bounded CCSDS input and output units.
 */

#ifndef AKIRA_CCSDS_UDP_H
#define AKIRA_CCSDS_UDP_H

#include "ccsds_profile.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ccsds_udp_stats {
    bool running;
    uint32_t datagrams_received;
    uint32_t datagrams_sent;
    int last_error;
};

/** Return whether the UDP transport is available in this build. */
bool ccsds_udp_available(void);

/**
 * Start receiving bounded CCSDS units from the configured local endpoint.
 *
 * Each UDP datagram is passed unchanged to the central CCSDS input profile.
 */
int ccsds_udp_start(struct ccsds_profile_input *input);

/** Stop the UDP receive listener. */
void ccsds_udp_stop(void);

/**
 * Send one encoded, bounded CCSDS unit to the configured UDP peer.
 *
 * The callback shape is compatible with the CFDP Space Packet adapter.
 */
int ccsds_udp_send(void *user, const uint8_t *unit, size_t unit_len);

/** Copy current UDP transport counters. */
void ccsds_udp_get_stats(struct ccsds_udp_stats *stats);

/**
 * Pass one acquired datagram through the central input profile.
 *
 * This is exposed so non-socket acquisition tests can verify the transport
 * handoff without duplicating profile selection logic.
 */
int ccsds_udp_dispatch_datagram(struct ccsds_profile_input *input,
                                const uint8_t *unit, size_t unit_len);

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_UDP_H */
