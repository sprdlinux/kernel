#include <linux/list.h>
#include <linux/sdiom_tx_api.h>

#include "sdiom_depend.h"
#include "sdiom_rx_recvbuf.h"
#include "sdiom_rx_parser.h"
#include "sdiom_type.h"

#define RX_PUH_SIZE sizeof(struct sdiom_rx_puh_t)

#define RX_WRONG_DATA_DEBUG

unsigned int sdiom_rx_parser_total_packet(struct sdiom_rx_recvbuf_t *rbuf)
{
	unsigned int cnt = 0, i = 0;
	unsigned int cnt_dummy = 0;
	unsigned int cnt_all = 0;
	struct sdiom_rx_puh_t *puh = NULL;
	unsigned char *p = NULL;
	char assert_str[64];

	/* If assert or dump memory happened, not parse data again. */
	if (sdiom_get_carddump_status(false) != 0)
		return 0;

	atomic_set(&rbuf->total_packet, 0);
	atomic_set(&rbuf->free_packet, 0);

	puh = (struct sdiom_rx_puh_t *)rbuf->buf;

	for (cnt = 0; cnt < 0xFFFF;) {
		if (puh->eof == 0) {
			/* consider dummy packet */
			cnt_all++;

			sdiom_print
			    ("rx_total rbuf[%d]cnt[%d]type[%d]sub[%d]len[%d]\n",
			     rbuf->index, cnt_all, puh->type, puh->subtype,
			     puh->len);

			if (puh->type != 0xF) {

#ifdef RX_WRONG_DATA_DEBUG
				if ((puh->type >= SDIOM_RX_TYPE_MAX) ||
					(puh->subtype >= SDIOM_RX_SUB_MAX) ||
					(puh->len > SDIOM_RX_RECVBUF_LEN) ||
						(puh->len == 0)) {

					sdiom_err("sdiom:rx rbuf[%d] err[%d]type[%d]sub[%d]len[%d]\n",
						rbuf->index, cnt,
						puh->type, puh->subtype,
						puh->len);
					sdiom_err("sdiom:rx rbuf[%d] rbuf->buf:%p puh:%p\n",
						rbuf->index, rbuf->buf, puh);

					switch (puh->type) {
					case SDIOM_TYPE_BT:
						sprintf(assert_str,
							"BT rx err! type[%d]sub[%d]len[%d]",
							puh->type, puh->subtype,
							puh->len);
						break;
					case SDIOM_TYPE_FM:
						sprintf(assert_str,
							"FM rx err! type[%d]sub[%d]len[%d]",
							puh->type, puh->subtype,
							puh->len);
						break;
					case SDIOM_TYPE_WIFI:
						sprintf(assert_str,
							"WIFI rx err! type[%d]sub[%d]len[%d]",
							puh->type, puh->subtype,
							puh->len);
						break;
					case SDIOM_TYPE_BSP:
						sprintf(assert_str,
							"BSP rx err! type[%d]sub[%d]len[%d]",
							puh->type, puh->subtype,
							puh->len);
						break;
					default:
						sprintf(assert_str,
							"ap sdiom type[%d]sub[%d]len[%d]",
							puh->type, puh->subtype,
							puh->len);
					}

					for (i = 0; i < (puh->len
						< 10 ? puh->len:10); i++)
						sdiom_err("%s i:%d 0x%x\n",
							__func__, i,
							rbuf->buf[i]);
					mdbg_assert_interface(assert_str);

					break;
				}
#endif
				cnt++;
			} else
				cnt_dummy++;

			p = (unsigned char *)puh;
			p = p + RX_PUH_SIZE + SDIOM_ALIGN_32BIT(puh->len);
			puh = (struct sdiom_rx_puh_t *)p;
		} else
			break;
	}

	sdiom_print("sdiom:rx_total rbuf[%d] cnt[%d] cnt_dummy[%d]\n",
		    rbuf->index, cnt, cnt_dummy);

	atomic_set(&rbuf->total_packet, cnt);

	/* if pure dummy stream let the buf free */
	if (cnt == 0)
		atomic_set(&rbuf->busy, 0);

	return cnt;
}

void sdiom_rx_parser(struct sdiom_rx_recvbuf_t *rbuf)
{
	unsigned int cnt = 0;
	unsigned int cnt_dummy = 0;
	struct sdiom_rx_puh_t *puh = NULL;
	unsigned char *p = NULL;

	SDIOM_PT_RX_PROCESS_CALLBACK rx_process_cb = NULL;

	/* not deal with pure dummy stream */
	if (atomic_read(&rbuf->total_packet) == 0)
		return;

	puh = (struct sdiom_rx_puh_t *)rbuf->buf;

	for (cnt = 0; cnt < 0xFFFF;) {
		if (puh->eof == 0) {
			p = (unsigned char *)puh;

			/* parse info and send to callback */

			if (puh->type != 0xF) {

#ifdef RX_WRONG_DATA_DEBUG
				if ((puh->type >= SDIOM_RX_TYPE_MAX) ||
					(puh->subtype >= SDIOM_RX_SUB_MAX) ||
					(puh->len > SDIOM_RX_RECVBUF_LEN) ||
						(puh->len == 0)) {

					sdiom_err("sdiom:skip[%d]type[%d]sub[%d]len[%d]\n",
					cnt, puh->type, puh->subtype, puh->len);

					break;
				}
#endif

				cnt++;
				sdiom_rx_cb_lock();
				rx_process_cb =
				    sdiom_rx_callback_get(puh->type,
							  puh->subtype);

				if (rx_process_cb != NULL) {
					rx_process_cb((p + RX_PUH_SIZE),
						      puh->len, rbuf->index);
				} else
					sdiom_rx_packet_release(rbuf->index);
				sdiom_rx_cb_unlock();

			} else
				cnt_dummy++;
			/* pointer to next packet */

			p = p + RX_PUH_SIZE + SDIOM_ALIGN_32BIT(puh->len);
			puh = (struct sdiom_rx_puh_t *)p;
		} else
			break;
	}
}
