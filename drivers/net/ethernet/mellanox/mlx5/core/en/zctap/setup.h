#ifndef _MLX5_EN_ZCTAP_SETUP_H
#define _MLX5_EN_ZCTAP_SETUP_H

#include <linux/skbuff.h>
#include <net/zctap.h>

#if IS_ENABLED(CONFIG_ZCTAP)

static inline void
mlx5e_zcopy_set(struct sk_buff *skb, struct mlx5e_rq *rq)
{
	skb_zcopy_init(skb, &rq->zctap_ifq->uarg);
}

static inline dma_addr_t
mlx5e_zctap_get_frag_dma(struct sk_buff *skb, skb_frag_t *frag)
{
	struct zctap_skq *skq = skb_shinfo(skb)->destructor_arg;

	return zctap_frag_for_device(skq->ctx, frag);
}

static inline int
mlx5e_zctap_get_page(struct mlx5e_rq *rq, struct mlx5e_dma_info *dma_info)
{
	struct zctap_ifq *ifq = rq->zctap_ifq;

	return zctap_get_page(ifq, &dma_info->page, &dma_info->addr);
}

static inline void
mlx5e_zctap_put_page(struct mlx5e_rq *rq, struct mlx5e_dma_info *dma_info,
		     bool recycle)
{
	struct zctap_ifq *ifq = rq->zctap_ifq;
	struct page *page = zctap_raw_page(dma_info->page);

	if (page) {
		put_page(page);
		zctap_put_page(ifq, page, recycle);
	}
}

static inline bool
mlx5e_zctap_page(struct page *page)
{
	return zctap_page(page);
}

static inline struct page *
mlx5e_zctap_rx_data(struct mlx5e_rq *rq, struct mlx5e_dma_info *di,
		    u32 frag_offset, u32 len)
{
	struct page *page = di->page;

	if (zctap_page_sync(page))
                dma_sync_single_for_cpu(rq->pdev,
                                        di->addr + frag_offset,
                                        len, DMA_FROM_DEVICE);
	di->page = NULL;
	return zctap_raw_page(page);
}

static inline bool
mlx5e_zctap_avail(struct mlx5e_rq *rq, u8 count)
{
	struct zctap_ifq *ifq = rq->zctap_ifq;

	/* XXX
	 * napi_cache_count is not a total count, and this also
	 * doesn't consider any_cache_count.
	 */
	return ifq->napi_cache_count >= count ||
		sq_cons_avail(&ifq->fill, count - ifq->napi_cache_count);
}

static inline void
mlx5e_zctap_taken(struct mlx5e_rq *rq)
{
	struct zctap_ifq *ifq = rq->zctap_ifq;

	sq_cons_complete(&ifq->fill);
}

struct zctap_ifq *
mlx5e_zctap_get_ifq(struct mlx5e_params *params, struct mlx5e_xsk *xsk,
                     u16 ix);

int
mlx5e_zctap_setup_ifq(struct net_device *dev, struct zctap_ifq *ifq,
		       u16 *qid);

int mlx5e_open_zctap(struct mlx5e_priv *priv, struct mlx5e_params *params,
		      struct zctap_ifq *ifq, struct mlx5e_channel *c);

void mlx5e_close_zctap(struct mlx5e_channel *c);

void mlx5e_deactivate_zctap(struct mlx5e_channel *c);

int mlx5e_zctap_redirect_rqts_to_channels(struct mlx5e_priv *priv,
					    struct mlx5e_channels *chs);

void mlx5e_zctap_redirect_rqts_to_drop(struct mlx5e_priv *priv,
					struct mlx5e_channels *chs);

#else

#define mlx5e_zctap_get_dma(skb, frag)				0
#define mlx5e_zctap_get_page(rq, dma_info)			0
#define mlx5e_zctap_put_page(rq, dma_info, recycle)
#define mlx5e_zctap_avail(rq, u8)				false
#define mlx5e_zctap_taken(rq)
#define mlx5e_zctap_get_ifq(params, xsk, ix)			NULL
#define mlx5e_zctap_setup_ifq(dev, ifq, qid)			-EINVAL
#define mlx5e_open_zctap(priv, params, ifq, c)			-EINVAL
#define mlx5e_close_zctap(c)
#define mlx5e_deactivate_zctap(c)
#define mlx5e_zctap_redirect_rqts_to_channels(priv, chs)	/* ignored */
#define mlx5e_zctap_redirect_rqts_to_drop(priv, chs)

#endif /* IS_ENABLED(CONFIG_ZCTAP) */

#endif /* _MLX5_EN_ZCTAP_SETUP_H */
