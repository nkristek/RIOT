/*
 * Copyright (C) 2018 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    TODO
 * @ingroup     TODO
 * @brief       TODO
 * @{
 *
 * @file
 * @brief       TODO
 *
 * @author      Hauke Petersen <hauke.petersen@fu-berlin.de>
 */

#ifndef PKTCNT_H
#define PKTCNT_H

#include <stdint.h>

#include "net/gnrc/pkt.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef MODULE_PKTCNT_FAST
// following counters are only for fast mode
extern uint32_t retransmissions;
extern uint32_t tx_interest;
extern uint32_t tx_data;
extern uint32_t rx_interest;
extern uint32_t rx_data;
extern uint32_t netdev_evt_tx_noack;
extern uint32_t tx_pam;
extern uint32_t tx_nam;
extern uint32_t tx_sol;
extern uint32_t rx_nam;
extern uint32_t rx_pam;
extern uint32_t rx_sol;
void pktcnt_fast_print(void);
#endif

enum {
    PKTCNT_OK = 0,
    PKTCNT_ERR_INIT = -1,
};

int pktcnt_init(void);
void pktcnt_timer_init(void);

void pktcnt_log_rx(gnrc_pktsnip_t *pkt);
void pktcnt_log_tx(gnrc_pktsnip_t *pkt);

#ifdef __cplusplus
}
#endif

#endif /* PKTCNT_H */
/** @} */
