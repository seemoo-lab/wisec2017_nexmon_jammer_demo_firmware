/***************************************************************************
 *                                                                         *
 *          ###########   ###########   ##########    ##########           *
 *         ############  ############  ############  ############          *
 *         ##            ##            ##   ##   ##  ##        ##          *
 *         ##            ##            ##   ##   ##  ##        ##          *
 *         ###########   ####  ######  ##   ##   ##  ##    ######          *
 *          ###########  ####  #       ##   ##   ##  ##    #    #          *
 *                   ##  ##    ######  ##   ##   ##  ##    #    #          *
 *                   ##  ##    #       ##   ##   ##  ##    #    #          *
 *         ############  ##### ######  ##   ##   ##  ##### ######          *
 *         ###########    ###########  ##   ##   ##   ##########           *
 *                                                                         *
 *            S E C U R E   M O B I L E   N E T W O R K I N G              *
 *                                                                         *
 * This file is part of NexMon.                                            *
 *                                                                         *
 * Copyright (c) 2016 NexMon Team                                          *
 *                                                                         *
 * NexMon is free software: you can redistribute it and/or modify          *
 * it under the terms of the GNU General Public License as published by    *
 * the Free Software Foundation, either version 3 of the License, or       *
 * (at your option) any later version.                                     *
 *                                                                         *
 * NexMon is distributed in the hope that it will be useful,               *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of          *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           *
 * GNU General Public License for more details.                            *
 *                                                                         *
 * You should have received a copy of the GNU General Public License       *
 * along with NexMon. If not, see <http://www.gnu.org/licenses/>.          *
 *                                                                         *
 **************************************************************************/

#pragma NEXMON targetregion "patch"

#include <firmware_version.h>   // definition of firmware version macros
#include <wrapper.h>            // wrapper definitions for functions that already exist in the firmware
#include <structs.h>            // structures that are used by the code in the firmware
#include <helper.h>             // useful helper functions
#include <patcher.h>            // macros used to craete patches such as BLPatch, BPatch, ...
#include <nexioctls.h>          // ioctls added in the nexmon patch
#include <argprintf.h>          // allows to execute argprintf to print into the arg buffer
#include <localsendframe.h>
#include <rates.h>              // rates used to build the ratespec for frame injection
#include <signalgeneration.h>

extern void send_udp_frame(struct wl_info *wl, uint32 timestamp, uint16 port, bool fcs_error);


#define SHM(x) (x)
#define QOSDATA                     SHM(0x1340)
#define BEACON                      SHM(0x1342)
#define OTHER                       SHM(0x1344)
#define QOSDATA_TARGET_MAC          SHM(0x1346)
#define ACK                         SHM(0x1348)
#define SENDACK                     SHM(0x134A)

#define TARGET_PORT_FOUND           SHM(0x1352)
#define PACKLATE                    SHM(0x1354)

#define DELTACLOCK1                 SHM(0x1360)
#define DELTACLOCK2                 SHM(0x1362)
#define DELTACLOCK3                 SHM(0x1364)

#define JAMMER_TYPE                 SHM(0x1372)
#define JAMMER_TYPE_DISABLED        0
#define JAMMER_TYPE_SIMPLE          1
#define JAMMER_TYPE_ACKNOWLEDGING   2
#define JAMMER_TARGET_PORT          SHM(0x1374)
#define JAMMER_IDFT_SIZE            SHM(0x1376)
#define JAMMER_LOOP_COUNT           SHM(0x1378)

#define wreg32(r, v)        (*(volatile uint32*)(r) = (uint32)(v))
#define rreg32(r)       (*(volatile uint32*)(r))
#define wreg16(r, v)        (*(volatile uint16*)(r) = (uint16)(v))
#define rreg16(r)       (*(volatile uint16*)(r))
#define wreg8(r, v)     (*(volatile uint8*)(r) = (uint8)(v))
#define rreg8(r)        (*(volatile uint8*)(r))

#define BCM_REFERENCE(data) ((void)(data))

#define R_REG(osh, r) ({ \
    __typeof(*(r)) __osl_v; \
    BCM_REFERENCE(osh); \
    switch (sizeof(*(r))) { \
    case sizeof(uint8): __osl_v = rreg8((void *)(r)); break; \
    case sizeof(uint16):    __osl_v = rreg16((void *)(r)); break; \
    case sizeof(uint32):    __osl_v = rreg32((void *)(r)); break; \
    } \
    __osl_v; \
})
#define W_REG(osh, r, v) do { \
    BCM_REFERENCE(osh); \
    switch (sizeof(*(r))) { \
    case sizeof(uint8): wreg8((void *)(r), (v)); break; \
    case sizeof(uint16):    wreg16((void *)(r), (v)); break; \
    case sizeof(uint32):    wreg32((void *)(r), (v)); break; \
    } \
} while (0)

static uint32 timestamp = 0;
static uint16 ports[] = { 4040, 3939 };

static void
send_udp_frame_handler(struct hndrte_timer *t)
{
	struct wlc_info *wlc = (struct wlc_info *) t->data;
	struct wl_info *wl = wlc->wl;
	bool random_fcs_error = R_REG(wlc->osh, &wlc->regs->u.d11regs.tsf_random) % 2;
	uint16 random_port = ports[R_REG(wlc->osh, &wlc->regs->u.d11regs.tsf_random) % (sizeof(ports)/sizeof(ports[0]))];

	//printf("udp: %d %d %d\n", timestamp, random_port, random_fcs_error);

	send_udp_frame(wl, timestamp++, random_port, random_fcs_error);
}

static void
init_send_udp_frame_task(struct wlc_info *wlc)
{
	struct hndrte_timer *t;

    t = hndrte_init_timer(init_send_udp_frame_task, wlc, send_udp_frame_handler, 0);

    if (!hndrte_add_timer(t, 100, 1)) {
        hndrte_free_timer(t);

        printf("ERR: could not add timer");
    }
}

struct udpstream {
    uint8 id;
    uint8 power;
    uint16 fps;
    uint16 destPort;
    uint8 modulation;
    uint8 rate;
    uint8 bandwidth;
    uint8 ldpc;
} __attribute__((packed));

struct jamming_settings {
    uint16 idftSize;
    uint16 port;
    int16 numActiveSubcarriers;
    uint8 jammingType;
    uint16 jammingSignalRepetitions;
    int8 power;
    cint16ap freqDomSamps[];
} __attribute__((packed));

static struct tx_task *tx_task_list[10] = { 0 };

struct wlandata_header {
    uint8 ver_type_subtype;
    uint8 flags;
    uint16 duration;
    uint8 dst_addr[6];
    uint8 src_addr[6];
    uint8 bssid[6];
    uint16 frag_seq_num;
    uint16 qos_ctrl;
    uint8 llc_dsap;
    uint8 llc_ssap;
    uint8 llc_ctrl;
    uint8 llc_org_code[3];
    uint16 llc_type;
} __attribute__((packed));

struct wlandata_ipv4_udp_header {
    struct wlandata_header wlan;
    struct ip_header ip;
    struct udp_header udp;
    uint8 payload[];
} __attribute__((packed));

struct wlandata_ipv4_udp_header wlandata_ipv4_udp_header = {
    .wlan = {
        .ver_type_subtype = 0x88,
        .flags = 0x00,
        .duration = 0x013a,
        .dst_addr = { 'N', 'E', 'X', 'M', 'O', 'N' },
        .src_addr = { 'J', 'A', 'M', 'M', 'E', 'R' },
        .bssid = { 'D', 'E', 'M', 'O', 0, 0 },
        .frag_seq_num = 0x0000,
        .qos_ctrl = 0x0000,
        .llc_dsap = 0xaa,
        .llc_ssap = 0xaa,
        .llc_ctrl = 0x03,
        .llc_org_code = { 0x00, 0x00, 0x00 },
        .llc_type = 0x0008,
    },
    .ip = {
        .version_ihl = 0x45,
        .dscp_ecn = 0x00,
        .total_length = 0x0000,
        .identification = 0x0100,
        .flags_fragment_offset = 0x0000,
        .ttl = 0x01, 
        .protocol = 0x11,
        .header_checksum = 0x0000,
        .src_ip.array = { 10, 10, 10, 10 },
        .dst_ip.array = { 255, 255, 255, 255 }
    },
    .udp = {
        .src_port = HTONS(5500),
        .dst_port = HTONS(5500),
        .len_chk_cov.length = 0x0000,
        .checksum = 0x0000
    },
};

/**
 * Calculates the IPv4 header checksum given the total IPv4 packet length.
 *
 * This checksum is specific to the packet format above. This is not a full
 * implementation of the checksum algorithm. Instead, as much as possible is
 * precalculated to reduce the amount of computation needed. This calculation
 * is accurate for total lengths up to 42457.
 */
static inline uint16_t
calc_checksum(uint16_t total_len)
{
    return ~(23078 + total_len);
}

void
prepend_wlandata_ipv4_udp_header(struct sk_buff *p, uint16 destPort)
{
    wlandata_ipv4_udp_header.ip.total_length = htons(p->len + sizeof(struct ip_header) + sizeof(struct udp_header));
    wlandata_ipv4_udp_header.ip.header_checksum = htons(calc_checksum(p->len + sizeof(struct ip_header) + sizeof(struct udp_header)));
    wlandata_ipv4_udp_header.udp.len_chk_cov.length = htons(p->len + sizeof(struct udp_header));
    wlandata_ipv4_udp_header.udp.src_port = htons(destPort);
    wlandata_ipv4_udp_header.udp.dst_port = htons(destPort);

    skb_push(p, sizeof(wlandata_ipv4_udp_header));
    memcpy(p->data, &wlandata_ipv4_udp_header, sizeof(wlandata_ipv4_udp_header));
}

static void
exp_set_gains_by_index_change_bbmult(struct phy_info *pi, int8 index, int8 bbmultmult)
{
    ac_txgain_setting_t gains = { 0 };
    wlc_phy_txpwrctrl_enable_acphy(pi, 0);
    wlc_phy_get_txgain_settings_by_index_acphy(pi, &gains, index);
    gains.bbmult *= bbmultmult;
    wlc_phy_txcal_txgain_cleanup_acphy(pi, &gains);
}

static void
set_power_index(struct phy_info *pi, int8 index) {
    if (index < 0) {
        wlc_phy_txpwrctrl_enable_acphy(pi, 1);
    } else {
        exp_set_gains_by_index_change_bbmult(pi, index, 1);
    }
}

static uint8 *orig_etheraddr = 0;

static void
change_etheraddr(struct wlc_info *wlc, uint8 *newaddr) {
    if (orig_etheraddr == 0) {
        orig_etheraddr = malloc(4, 0);
        memcpy(orig_etheraddr, wlc->pub->cur_etheraddr, 6);
    }
    wlc_iovar_op(wlc, "cur_etheraddr", NULL, 0, newaddr, 6, 1, 0);
}

static uint8 *
get_orig_etheraddr(struct wlc_info *wlc) {
    if (orig_etheraddr == 0) {
        orig_etheraddr = malloc(4, 0);
        memcpy(orig_etheraddr, wlc->pub->cur_etheraddr, 6);
    }

    return orig_etheraddr;
}

int
wlc_ioctl_5xx(struct wlc_info *wlc, int cmd, char *arg, int len, void *wlc_if)
{
    int ret = IOCTL_ERROR;
    struct osl_info *osh = wlc->osh;
    struct phy_info *pi = wlc->hw->band->pi;

    switch (cmd) {
    	case 500:
		{
			// Turn of MPC to be able to use random numbers
			int mpc = 0;
            wlc_iovar_op(wlc, "mpc", 0, 0, &mpc, 4, 1, 0);

			init_send_udp_frame_task(wlc);
			ret = IOCTL_SUCCESS;
		}
		break;

		case 501:
		{
            // deactivate scanning
            set_scansuppress(wlc, 1);
            
            // deactivate minimum power consumption
            set_mpc(wlc, 0);

            // set the channel
            set_chanspec(wlc, 0x1001);

            // set mac address to "JAMMER"
            //wlc_iovar_op(wlc, "cur_etheraddr", NULL, 0, "JAMMER", 6, 1, 0);
            change_etheraddr(wlc, (uint8 *) "JAMMER");

            // deactivate the transmission of ampdus
            wlc_ampdu_tx_set(wlc->ampdu_tx, 0);

            // set the retransmission settings
            set_intioctl(wlc, WLC_SET_LRL, 7);
            set_intioctl(wlc, WLC_SET_SRL, 6);

            // setting the rate spec here allows to activate LDPC in 802.11n frames
            wlc->band->rspec_override = RATES_OVERRIDE_MODE | RATES_ENCODE_HT | RATES_BW_20MHZ | RATES_HT_MCS(0) | RATES_LDPC_CODING;

            unsigned int fifo = 0;
            unsigned int rate = 0;
            int txdelay = 0;
            int txrepetitions = -1;
            int txperiodicity = 100;

            uint16 payload_length = 1000;

            struct sk_buff *p = pkt_buf_get_skb(osh, sizeof(wlandata_ipv4_udp_header) + payload_length + 202);
            
            // pull to have space for d11txhdrs
            skb_pull(p, 202);
            
            // pull as prepend_wlandata_ipv4_udp_header pushes
            skb_pull(p, sizeof(wlandata_ipv4_udp_header));

            memset(p->data, 0x23, payload_length);
            snprintf(p->data, payload_length, 
                "This frame is part of the \"Demonstrating Smartphone-based Jammers\" demo presented at ACM WiSec 2017. " 
                "It was transmitted by a Nexus 5 smartphone using Nexmon, the C-based firmware patching framework (https://nexmon.org).");

            uint8 *macaddr = get_orig_etheraddr(wlc);
            memcpy(&wlandata_ipv4_udp_header.wlan.bssid[4], &macaddr[4], 2);
            prepend_wlandata_ipv4_udp_header(p, 5500);

            wlc_d11hdrs_ext(wlc, p, wlc->band->hwrs_scb, 0, 0, 1, 1, 0, 0, 0 /* data_rate */, 0);
            p->scb = wlc->band->hwrs_scb;

            sendframe_with_timer(wlc, p, fifo, rate, txdelay, txrepetitions, txperiodicity);
            ret = IOCTL_SUCCESS;
        }
        break;

        case 502: // set jammer type
        {
            if (wlc->hw->up && len > 1) {
                wlc_suspend_mac_and_wait(wlc);
                wlc_bmac_write_shm(wlc->hw, JAMMER_TYPE, *(uint16 *) arg);
                wlc_enable_mac(wlc);
                ret = IOCTL_SUCCESS;
            }
            break;
        }

        case 503: // get jammer type
        {
            if (wlc->hw->up && len > 1) {
                wlc_suspend_mac_and_wait(wlc);
                *(uint16 *) arg = wlc_bmac_read_shm(wlc->hw, JAMMER_TYPE);
                wlc_enable_mac(wlc);
                ret = IOCTL_SUCCESS;
            }
            break;
        }

        case 504: // prepare jamming tone
        {
            set_scansuppress(wlc, 1);
            set_mpc(wlc, 0);
            set_chanspec(wlc, 0x1001);

            pi->pi_ac->deaf_count = 0;
            wlc_phyreg_enter(pi);
            wlc_suspend_mac_and_wait(wlc);
            wlc_phy_stay_in_carriersearch_acphy(pi, 1);

            int32 num_samps = 512;
            uint16 loop_count = 11;

            wlc_bmac_write_shm(wlc->hw, JAMMER_TARGET_PORT, htons(5500));
            //wlc_bmac_write_shm(wlc->hw, JAMMER_TYPE, JAMMER_TYPE_DISABLED);
            wlc_bmac_write_shm(wlc->hw, JAMMER_TYPE, JAMMER_TYPE_SIMPLE);
            //wlc_bmac_write_shm(wlc->hw, JAMMER_TYPE, JAMMER_TYPE_ACKNOWLEDGING);
            wlc_bmac_write_shm(wlc->hw, JAMMER_IDFT_SIZE, num_samps - 1);
            wlc_bmac_write_shm(wlc->hw, JAMMER_LOOP_COUNT, loop_count - 1);

            cint16ap *freq_dom_samps = (cint16ap *) malloc(sizeof(cint16ap) * num_samps, 0);
            memset(freq_dom_samps, 0, sizeof(cint16ap) * num_samps);

            exp_set_gains_by_index_change_bbmult(pi, 50, 1);

            //printf("using 20MHz pilots for jamming\n");
            freq_dom_samps[IDFTCARRIER20(-21, num_samps)].amplitude = 250;
            freq_dom_samps[IDFTCARRIER20(-21, num_samps)].phase = 0;

            freq_dom_samps[IDFTCARRIER20(-7, num_samps)].amplitude = 250;
            freq_dom_samps[IDFTCARRIER20(-7, num_samps)].phase = 0;

            freq_dom_samps[IDFTCARRIER20(7, num_samps)].amplitude = 250;
            freq_dom_samps[IDFTCARRIER20(7, num_samps)].phase = 0;

            freq_dom_samps[IDFTCARRIER20(21, num_samps)].amplitude = 250;
            freq_dom_samps[IDFTCARRIER20(21, num_samps)].phase = 180;

            my_phy_tx_ifft_acphy_ext(pi, freq_dom_samps, 0 /* iqmode */, 0 /* mac_based */, 0 /* modify_bbmult */, 1 /* runsamples */, 0xffff /* loops */, num_samps);
            udelay(1000000);
            wlc_phy_stopplayback_acphy(pi);

            free(freq_dom_samps);

            wlc_phy_stay_in_carriersearch_acphy(pi, 0);
            wlc_enable_mac(wlc);
            wlc_phyreg_exit(pi);

            // alternative to wlc_phy_stay_in_carriersearch_acphy
            pi->pi_ac->deaf_count = 10000;
            wlc_phy_clip_det_acphy(pi, 0);
            printf("Table tone set done, set chanspec %04x, scan suppressed, carrier search = %d\n", get_chanspec(wlc), pi->pi_ac->deaf_count);

            ret = IOCTL_SUCCESS;
            break;
        }

        case 505: // deactivate jammer
        {
            if (wlc->hw->up) {
                set_scansuppress(wlc, 1);
                set_mpc(wlc, 0);

                pi->pi_ac->deaf_count = 0;
                wlc_phyreg_enter(pi);
                wlc_suspend_mac_and_wait(wlc);
                wlc_phy_stay_in_carriersearch_acphy(pi, 1);
                wlc_bmac_write_shm(wlc->hw, JAMMER_TYPE, JAMMER_TYPE_DISABLED);
                wlc_phy_stay_in_carriersearch_acphy(pi, 0);
                wlc_enable_mac(wlc);
                wlc_phyreg_exit(pi);

                ret = IOCTL_SUCCESS;
            }
            break;
        }

        case 506: // set jammer target port
        {
            if (wlc->hw->up && len > 1) {
                wlc_suspend_mac_and_wait(wlc);
                wlc_bmac_write_shm(wlc->hw, JAMMER_TARGET_PORT, htons(*(uint16 *) arg));
                wlc_enable_mac(wlc);
                ret = IOCTL_SUCCESS;
            }
            break;
        }

        case 507: // get jammer target port
        {
            if (wlc->hw->up && len > 1) {
                wlc_suspend_mac_and_wait(wlc);
                *(uint16 *) arg = ntohs(wlc_bmac_read_shm(wlc->hw, JAMMER_TARGET_PORT));
                wlc_enable_mac(wlc);
                ret = IOCTL_SUCCESS;
            }
            break;
        }

        case 508:
        {
            // set mac address to "NEXMON"
            //wlc_iovar_op(wlc, "cur_etheraddr", NULL, 0, "NEXMON", 6, 1, 0);
            change_etheraddr(wlc, (uint8 *) "NEXMON");
            ret = IOCTL_SUCCESS;
            break;
        }

        case 510: // start stream according to parameters
        {
            if (len == sizeof(struct udpstream)) {
                struct udpstream *config = (struct udpstream *) arg;

                if (config->id >= ARRAYSIZE(tx_task_list)) {
                    printf("too many udp streams");
                    break;
                }

                if (tx_task_list[config->id] != 0) {
                    // end the task automatically at its next execution
                    tx_task_list[config->id]->txrepetitions = 0;
                    tx_task_list[config->id] = 0;
                }

                set_scansuppress(wlc, 1);
                set_mpc(wlc, 0);

                // deactivate the transmission of ampdus
                wlc_ampdu_tx_set(wlc->ampdu_tx, 0);

                // set the retransmission settings
                set_intioctl(wlc, WLC_SET_LRL, 7);
                set_intioctl(wlc, WLC_SET_SRL, 6);

                // set mac address to "JAMMER"
                //wlc_iovar_op(wlc, "cur_etheraddr", NULL, 0, "JAMMER", 6, 1, 0);
                change_etheraddr(wlc, (uint8 *) "JAMMER");

                unsigned int fifo = 0;
                unsigned int rate = 0;
                int txdelay = 0;
                int txrepetitions = -1;
                int txperiodicity = 1000 / config->fps;

                // setting the rate spec here allows to activate LDPC in 802.11n frames
                //wlc->band->rspec_override = RATES_OVERRIDE_MODE | RATES_ENCODE_HT | RATES_BW_20MHZ | RATES_HT_MCS(0) | RATES_LDPC_CODING;

                switch (config->modulation) {
                    case 0: // 802.11b
                    {
                        rate = config->rate * 2;
                    }
                    break;
                    
                    case 1: // 802.11a/g
                    {
                        rate = config->rate * 2;
                    }
                    break;

                    case 2: // 802.11n
                    {
                        rate = RATES_OVERRIDE_MODE | RATES_ENCODE_HT | RATES_HT_MCS(config->rate) | (config->ldpc ? RATES_LDPC_CODING : 0);
                    }
                    break;

                    case 3: // 802.11ac
                    {
                        rate = RATES_OVERRIDE_MODE | RATES_ENCODE_VHT | RATES_VHT_MCS(config->rate) | RATES_VHT_NSS(1);
                    }
                    break;
                }

                switch (config->bandwidth) {
                    case 20:
                    {
                        rate |= RATES_BW_20MHZ;
                    }
                    break;

                    case 40:
                    {
                        rate |= RATES_BW_40MHZ;
                    }
                    break;

                    case 80:
                    {
                        rate |= RATES_BW_80MHZ;
                    }
                    break;
                }

                uint16 payload_length = 1000;

                struct sk_buff *p = pkt_buf_get_skb(osh, sizeof(wlandata_ipv4_udp_header) + payload_length + 202);
                if (!p) break;

                // pull to have space for d11txhdrs
                skb_pull(p, 202);

                // pull as prepend_wlandata_ipv4_udp_header pushes
                skb_pull(p, sizeof(wlandata_ipv4_udp_header));

                memset(p->data, 0x23, payload_length);
                snprintf(p->data, payload_length, 
                    "This frame is part of the \"Demonstrating Smartphone-based Jammers\" demo presented at ACM WiSec 2017. " 
                    "It was transmitted by a Nexus 5 smartphone using Nexmon, the C-based firmware patching framework (https://nexmon.org).");

                uint8 *macaddr = get_orig_etheraddr(wlc);
                memcpy(&wlandata_ipv4_udp_header.wlan.bssid[4], &macaddr[4], 2);
                prepend_wlandata_ipv4_udp_header(p, config->destPort);

                wlc->band->rspec_override = rate;
                wlc_d11hdrs_ext(wlc, p, wlc->band->hwrs_scb, 0, 0, 1, 1, 0, 0, 0 /* data_rate */, 0);
                p->scb = wlc->band->hwrs_scb;

                tx_task_list[config->id] = sendframe_with_timer(wlc, p, fifo, rate, txdelay, txrepetitions, txperiodicity);

                printf("%s: starting stream\n", __FUNCTION__);
                
                ret = IOCTL_SUCCESS;
            }
            break;
        }

        case 511: // stops stream according to id
        {
            int id = (int) *(char *) arg;

            if (id >= ARRAYSIZE(tx_task_list)) {
                break;
            }

            if (tx_task_list[id] != 0) {
                // end the task automatically at its next execution
                tx_task_list[id]->txrepetitions = 0;
                tx_task_list[id] = 0;
            }

            ret = IOCTL_SUCCESS;
            break;
        }

        case 512: // set jammer receiver (activates filtering for NEXMONJAMMER MACs)
        {
            if (wlc->hw->up && len > 1) {
                wlc_suspend_mac_and_wait(wlc);
                //wlc_bmac_write_shm(wlc->hw, 0x1376, *(uint16 *) arg);
                wlc_enable_mac(wlc);
                ret = IOCTL_SUCCESS;
            }
            break;
        }

        case 513: // get jammer receiver
        {
            if (wlc->hw->up && len > 1) {
                wlc_suspend_mac_and_wait(wlc);
                //*(uint16 *) arg = wlc_bmac_read_shm(wlc->hw, 0x1376);
                wlc_enable_mac(wlc);
                ret = IOCTL_SUCCESS;
            }
            break;
        }

        case 514: // set jamming settings and start jamming
        {
            if (len >= sizeof(struct jamming_settings)) {
                struct jamming_settings *settings = (struct jamming_settings *) arg;
                
                if (len < settings->numActiveSubcarriers * sizeof(cint16ap) + sizeof(struct jamming_settings))
                    break;

                set_scansuppress(wlc, 1);
                set_mpc(wlc, 0);
                
                pi->pi_ac->deaf_count = 0;
                wlc_phyreg_enter(pi);
                wlc_suspend_mac_and_wait(wlc);
                wlc_phy_stay_in_carriersearch_acphy(pi, 1);

                wlc_bmac_write_shm(wlc->hw, JAMMER_TARGET_PORT, htons(settings->port));
                wlc_bmac_write_shm(wlc->hw, JAMMER_TYPE, settings->jammingType);
                wlc_bmac_write_shm(wlc->hw, JAMMER_IDFT_SIZE, settings->idftSize - 1);
                wlc_bmac_write_shm(wlc->hw, JAMMER_LOOP_COUNT, settings->jammingSignalRepetitions - 1);

                int32 num_samps = settings->idftSize;

                cint16ap *freq_dom_samps = (cint16ap *) malloc(sizeof(cint16ap) * num_samps, 0);
                memset(freq_dom_samps, 0, sizeof(cint16ap) * num_samps);

                set_power_index(pi, settings->power);

                int i;
                for (i = 0; i < settings->numActiveSubcarriers; i++) {
                    freq_dom_samps[IDFTCARRIER(i - settings->numActiveSubcarriers / 2, num_samps)].amplitude = settings->freqDomSamps[i].amplitude;
                    freq_dom_samps[IDFTCARRIER(i - settings->numActiveSubcarriers / 2, num_samps)].phase = settings->freqDomSamps[i].phase;
                    printf("%d %d %d\n", i, IDFTCARRIER(i - settings->numActiveSubcarriers / 2, num_samps), settings->freqDomSamps[i].amplitude);
                }
                
                my_phy_tx_ifft_acphy_ext(pi, freq_dom_samps, 0 /* iqmode */, 0 /* mac_based */, 0 /* modify_bbmult */, 1 /* runsamples */, 0xffff /* loops */, num_samps);
                udelay(1000000);
                wlc_phy_stopplayback_acphy(pi);

                free(freq_dom_samps);

                wlc_phy_stay_in_carriersearch_acphy(pi, 0);
                wlc_enable_mac(wlc);
                wlc_phyreg_exit(pi);

                // alternative to wlc_phy_stay_in_carriersearch_acphy
                pi->pi_ac->deaf_count = 10000;
                wlc_phy_clip_det_acphy(pi, 0);

                printf("starting jammer: power=%d\n", settings->power);

                ret = IOCTL_SUCCESS;
            }
            break;
        }

        case 515: // set jamming gain, if gain value set to -1, then hardware power control is enabled
        {
            if (len == 1) {
                set_power_index(pi, *(int8 *) arg);
            }
        }

        case 516: // for ucode-jammer.asm firmware
        {
            if (wlc->hw->up && len > 1) {
                wlc_suspend_mac_and_wait(wlc);
                argprintf("QOSDATA=%d BEACON=%d OTHER=%d QOSDATA_TARGET_MAC=%d\n", wlc_bmac_read_shm(wlc->hw, 0x1340), wlc_bmac_read_shm(wlc->hw, 0x1342), wlc_bmac_read_shm(wlc->hw, 0x1344), wlc_bmac_read_shm(wlc->hw, 0x1346));
                argprintf("ACK=%d, TARGET_PORT_FOUND=%d\n", wlc_bmac_read_shm(wlc->hw, 0x1348), wlc_bmac_read_shm(wlc->hw, 0x1352));
                wlc_enable_mac(wlc);
                
                ret = IOCTL_SUCCESS;
            }
            break;
        }
    }

    return ret;
}
