#ifndef _MLX5_EN_ZCTAP_SETUP_H
#define _MLX5_EN_ZCTAP_SETUP_H

#include <linux/skbuff.h>
#include <net/zctap.h>

#if IS_ENABLED(CONFIG_ZCTAP)

static inline dma_addr_t
mlx5e_zctap_get_frag_dma(struct sk_buff *skb, skb_frag_t *frag)
{
	struct zctap_skq *skq = skb_shinfo(skb)->destructor_arg;

	return zctap_get_frag_dma(skq->ctx, frag);
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
	struct page *page = dma_info->page;

	if (page)
		zctap_put_page(ifq, page, recycle);
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

void mlx5e_build_zctap_param(struct zctap_ifq *ifq,
			     struct mlx5e_extension_param *ext);

struct zctap_ifq *
mlx5e_zctap_get_ifq(struct mlx5e_params *params, u16 ix);

int
mlx5e_zctap_setup_ifq(struct net_device *dev, struct zctap_ifq *ifq,
		      u16 *qid);

int mlx5e_open_zctap(struct mlx5e_priv *priv, struct mlx5e_params *params,
		     struct mlx5e_extension_param *ext,
		     struct mlx5e_channel *c);

void mlx5e_close_zctap(struct mlx5e_channel *c);

void mlx5e_activate_zctap(struct mlx5e_channel *c);
void mlx5e_deactivate_zctap(struct mlx5e_channel *c);

int mlx5e_zctap_redirect_rqts_to_channels(struct mlx5e_priv *priv,
					  struct mlx5e_channels *chs);

void mlx5e_zctap_redirect_rqts_to_drop(struct mlx5e_priv *priv,
				       struct mlx5e_channels *chs);

struct sk_buff *
mlx5e_zctap_skb_from_cqe_nonlinear(struct mlx5e_rq *rq,
				   struct mlx5_cqe64 *cqe,
				   struct mlx5e_wqe_frag_info *wi,
				   u32 cqe_bcnt);

#else

#define mlx5e_zctap_get_frag_dma(skb, frag)			0
#define mlx5e_zctap_get_page(rq, dma_info)			0
#define mlx5e_zctap_put_page(rq, dma_info, recycle)
#define mlx5e_zctap_avail(rq, count)				false
#define mlx5e_zctap_taken(rq)
#define mlx5e_build_zctap_param(ifq, ext)
#define mlx5e_zctap_get_ifq(params, ix)				NULL
#define mlx5e_zctap_setup_ifq(dev, ifq, qid)			-EINVAL
#define mlx5e_open_zctap(priv, params, ext, c)			-EINVAL
#define mlx5e_close_zctap(c)
#define mlx5e_activate_zctap(c)
#define mlx5e_deactivate_zctap(c)
#define mlx5e_zctap_redirect_rqts_to_channels(priv, chs)	/* ignored */
#define mlx5e_zctap_redirect_rqts_to_drop(priv, chs)

static inline struct sk_buff *
mlx5e_zctap_skb_from_cqe_nonlinear(struct mlx5e_rq *rq,
				   struct mlx5_cqe64 *cqe,
				   struct mlx5e_wqe_frag_info *wi,
				   u32 cqe_bcnt)
{
	return NULL;
}

#endif /* IS_ENABLED(CONFIG_ZCTAP) */

#endif /* _MLX5_EN_ZCTAP_SETUP_H */
