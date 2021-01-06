#include "en.h"
#include "en/xdp.h"
#include "en/params.h"
#include "en/zctap.h"

struct zctap_ifq *
mlx5e_zctap_get_ifq(struct mlx5e_params *params, u16 ix)
{
	if (!params->zctap || !params->zctap->ifq_tbl)
		return NULL;

	if (unlikely(ix >= params->num_channels))
		return NULL;

	return params->zctap->ifq_tbl[ix];
}

static int
mlx5e_zctap_get_tbl(struct mlx5e_zctap *zctap)
{
	if (!zctap->ifq_tbl) {
		zctap->ifq_tbl = kcalloc(MLX5E_MAX_NUM_CHANNELS,
					 sizeof(*zctap->ifq_tbl), GFP_KERNEL);
		if (unlikely(!zctap->ifq_tbl))
			return -ENOMEM;
	}

	zctap->refcnt++;
	zctap->ever_used = true;

	return 0;
}

static void
mlx5e_zctap_put_tbl(struct mlx5e_zctap *zctap)
{
	if (!--zctap->refcnt) {
		kfree(zctap->ifq_tbl);
		zctap->ifq_tbl = NULL;
	}
}

static void
mlx5e_zctap_remove_ifq(struct mlx5e_zctap *zctap, u16 ix)
{
	zctap->ifq_tbl[ix] = NULL;

	mlx5e_zctap_put_tbl(zctap);
}

static int
mlx5e_zctap_add_ifq(struct mlx5e_zctap *zctap, struct zctap_ifq *ifq, u16 ix)
{
	int err;

	err = mlx5e_zctap_get_tbl(zctap);
	if (unlikely(err))
		return err;

	zctap->ifq_tbl[ix] = ifq;

	return 0;
}

static u16
mlx5e_zctap_find_unused_ifq(struct mlx5e_params *params)
{
	u16 ix;

	for (ix = 0; ix < params->num_channels; ix++) {
		if (mlx5e_extension_avail(params, ix))
			break;
	}
	return ix;
}

static int
mlx5e_redirect_zctap_rqt(struct mlx5e_priv *priv, u16 ix, u32 rqn)
{
	struct mlx5e_redirect_rqt_param direct_rrp = {
		.is_rss = false,
		{
			.rqn = rqn,
		},
	};

	u32 rqtn = priv->extension_tir[ix].rqt.rqtn;

	return mlx5e_redirect_rqt(priv, rqtn, 1, direct_rrp);
}

static int
mlx5e_zctap_redirect_rqt_to_channel(struct mlx5e_priv *priv,
				    struct mlx5e_channel *c)
{
	return mlx5e_redirect_zctap_rqt(priv, c->ix, c->xskrq.rqn);
}

static int
mlx5e_zctap_redirect_rqt_to_drop(struct mlx5e_priv *priv, u16 ix)
{
	return mlx5e_redirect_zctap_rqt(priv, ix, priv->drop_rq.rqn);
}

int
mlx5e_zctap_redirect_rqts_to_channels(struct mlx5e_priv *priv,
				      struct mlx5e_channels *chs)
{
	int err, i;

	for (i = 0; i < chs->num; i++) {
		struct mlx5e_channel *c = chs->c[i];

		if (!test_bit(MLX5E_CHANNEL_STATE_ZCTAP, c->state))
			continue;

		err = mlx5e_zctap_redirect_rqt_to_channel(priv, c);
		if (unlikely(err))
			goto err_stop;
	}

	return 0;

err_stop:
	for (i--; i >= 0; i--) {
		if (!test_bit(MLX5E_CHANNEL_STATE_ZCTAP, chs->c[i]->state))
			continue;

		mlx5e_zctap_redirect_rqt_to_drop(priv, i);
	}

	return err;
}

void
mlx5e_zctap_redirect_rqts_to_drop(struct mlx5e_priv *priv,
				  struct mlx5e_channels *chs)
{
	int i;

	for (i = 0; i < chs->num; i++) {
		if (!test_bit(MLX5E_CHANNEL_STATE_ZCTAP, chs->c[i]->state))
			continue;

		mlx5e_zctap_redirect_rqt_to_drop(priv, i);
	}
}

void
mlx5e_activate_zctap(struct mlx5e_channel *c)
{
	set_bit(MLX5E_RQ_STATE_ENABLED, &c->xskrq.state);

	spin_lock(&c->async_icosq_lock);
	mlx5e_trigger_irq(&c->async_icosq);
	spin_unlock(&c->async_icosq_lock);
}

void
mlx5e_deactivate_zctap(struct mlx5e_channel *c)
{
	mlx5e_deactivate_rq(&c->xskrq);
}

void
mlx5e_build_zctap_param(struct zctap_ifq *ifq,
			struct mlx5e_extension_param *ext)
{
	struct mlx5e_zctap_param *zctap = &ext->zctap;

	ext->type = MLX5E_EXT_ZCTAP;
	zctap->ifq = ifq;
	zctap->split_offset = ifq->split_offset;
}

static int
mlx5e_zctap_enable_locked(struct mlx5e_priv *priv,
			  struct zctap_ifq *ifq, u16 *qid)
{
	struct mlx5e_params *params = &priv->channels.params;
	struct mlx5e_extension_param ext;
	struct mlx5e_channel *c;
	int err;
	u16 ix;

	/* mlx5 doesn't really have header splitting */
	if (ifq->split != ZCTAP_SPLIT_NONE)
		return -EINVAL;

	if (*qid == (u16)-1) {
		ix = mlx5e_zctap_find_unused_ifq(params);
		if (ix >= params->num_channels)
			return -EBUSY;

		*qid = mlx5e_get_qid_for_ch_in_group(params, ix,
						     MLX5E_RQ_GROUP_EXTENSION);
	} else {
		if (!mlx5e_qid_get_ch_if_in_group(params, *qid,
						  MLX5E_RQ_GROUP_EXTENSION,
						  &ix))
			return -EINVAL;

		if (!mlx5e_extension_avail(params, ix))
			return -EBUSY;
	}

	err = mlx5e_zctap_add_ifq(&priv->zctap, ifq, ix);
	if (unlikely(err))
		return err;

	mlx5e_build_zctap_param(ifq, &ext);

	if (!test_bit(MLX5E_STATE_OPENED, &priv->state))
		goto validate_closed;

	c = priv->channels.c[ix];

	err = mlx5e_open_zctap(priv, params, &ext, c);
	if (unlikely(err))
		goto err_remove_ifq;

	mlx5e_activate_zctap(c);

	err = mlx5e_zctap_redirect_rqt_to_channel(priv, priv->channels.c[ix]);
	if (unlikely(err))
		goto err_deactivate;

	return 0;

err_deactivate:
	mlx5e_deactivate_zctap(c);
	mlx5e_close_zctap(c);

err_remove_ifq:
	mlx5e_zctap_remove_ifq(&priv->zctap, ix);

	return err;

validate_closed:
	return 0;
}

static int
mlx5e_zctap_disable_locked(struct mlx5e_priv *priv, u16 *qid)
{
	struct mlx5e_params *params = &priv->channels.params;
	struct mlx5e_channel *c;
	struct zctap_ifq *ifq;
	u16 ix;

	if (unlikely(!mlx5e_qid_get_ch_if_in_group(params, *qid,
						   MLX5E_RQ_GROUP_EXTENSION,
						   &ix)))
		return -EINVAL;

	ifq = mlx5e_zctap_get_ifq(params, ix);
	if (unlikely(!ifq))
		return -EINVAL;

	if (!test_bit(MLX5E_STATE_OPENED, &priv->state))
		goto remove_ifq;

	c = priv->channels.c[ix];
	mlx5e_zctap_redirect_rqt_to_drop(priv, ix);
	mlx5e_deactivate_zctap(c);
	mlx5e_close_zctap(c);

remove_ifq:
	mlx5e_zctap_remove_ifq(&priv->zctap, ix);

	return 0;
}

static int
mlx5e_zctap_enable_ifq(struct mlx5e_priv *priv, struct zctap_ifq *ifq, u16 *qid)
{
	int err;

	mutex_lock(&priv->state_lock);
	err = mlx5e_zctap_enable_locked(priv, ifq, qid);
	mutex_unlock(&priv->state_lock);

	return err;
}

static int
mlx5e_zctap_disable_ifq(struct mlx5e_priv *priv, u16 *qid)
{
	int err;

	mutex_lock(&priv->state_lock);
	err = mlx5e_zctap_disable_locked(priv, qid);
	mutex_unlock(&priv->state_lock);

	return err;
}

int
mlx5e_zctap_setup_ifq(struct net_device *dev, struct zctap_ifq *ifq, u16 *qid)
{
	struct mlx5e_priv *priv = netdev_priv(dev);

	return ifq ? mlx5e_zctap_enable_ifq(priv, ifq, qid) :
		     mlx5e_zctap_disable_ifq(priv, qid);
}

static int
mlx5e_init_zctap_rq(struct mlx5e_channel *c,
		    struct mlx5e_params *params,
		    struct mlx5e_extension_param *ext,
		    struct mlx5e_rq *rq)
{
	struct mlx5_core_dev *mdev = c->mdev;
	int rq_ix;
	int err;

	/* XXX fix mlx5e_open_rq so it gets type from here... */
	rq->wq_type	 = params->rq_wq_type;
	rq->pdev	 = c->pdev;
	rq->netdev	 = c->netdev;
	rq->priv	 = c->priv;
	rq->tstamp	 = c->tstamp;
	rq->clock	 = &mdev->clock;
	rq->icosq	 = &c->icosq;
	rq->ix		 = c->ix;
	rq->mdev	 = mdev;
	rq->hw_mtu	 = MLX5E_SW2HW_MTU(params, params->sw_mtu);
	rq->zctap_ifq	 = ext->zctap.ifq;
	rq->stats	 = &c->priv->channel_stats[c->ix].zctrq;
	rq->ptp_cyc2time = mlx5_rq_ts_translator(mdev);
	rq->buff.frame0_split = ext->zctap.split_offset;

	err = mlx5e_rq_set_handlers(rq, params, ext);
	if (err)
		return err;

        rq_ix = c->ix + params->num_channels * MLX5E_RQ_GROUP_EXTENSION;
        return xdp_rxq_info_reg(&rq->xdp_rxq, rq->netdev, rq_ix, 0);
}

static int
mlx5e_open_zctap_rq(struct mlx5e_channel *c, struct mlx5e_params *params,
		    struct mlx5e_rq_param *rq_params,
		    struct mlx5e_extension_param *ext)
{
	int err;

	err = mlx5e_init_zctap_rq(c, params, ext, &c->xskrq);
	if (err)
		return err;

	return mlx5e_open_rq(params, rq_params, ext, cpu_to_node(c->cpu),
			     &c->xskrq);
}

int
mlx5e_open_zctap(struct mlx5e_priv *priv, struct mlx5e_params *params,
		 struct mlx5e_extension_param *ext, struct mlx5e_channel *c)
{
	struct mlx5e_channel_param *cparam;
	struct mlx5e_create_cq_param ccp;
	int err;

	mlx5e_build_create_cq_param(&ccp, c);

	cparam = kvzalloc(sizeof(*cparam), GFP_KERNEL);
	if (!cparam)
		return -ENOMEM;

	mlx5e_build_rq_param(priv->mdev, params, ext, priv->q_counter,
			     &cparam->rq);

	err = mlx5e_open_cq(c->priv, params->rx_cq_moderation, &cparam->rq.cqp,
			    &ccp, &c->xskrq.cq);
	if (unlikely(err))
		goto err_free_cparam;

	err = mlx5e_open_zctap_rq(c, params, &cparam->rq, ext);
	if (unlikely(err))
		goto err_close_rx_cq;

	kvfree(cparam);

	set_bit(MLX5E_CHANNEL_STATE_ZCTAP, c->state);

	return 0;

err_close_rx_cq:
	mlx5e_close_cq(&c->xskrq.cq);

err_free_cparam:
	kvfree(cparam);

	return err;
}

void
mlx5e_close_zctap(struct mlx5e_channel *c)
{
	clear_bit(MLX5E_CHANNEL_STATE_ZCTAP, c->state);
	synchronize_rcu(); /* XXX Sync with the XSK wakeup. */

	mlx5e_close_rq(&c->xskrq);
	mlx5e_close_cq(&c->xskrq.cq);

	memset(&c->xskrq, 0, sizeof(c->xskrq));
}

static inline void
mlx5e_zctap_add_skb_frag(struct mlx5e_rq *rq, struct sk_buff *skb,
			 struct mlx5e_dma_info *di, u32 frag_offset, u32 len,
			 unsigned int truesize)
{
	struct page *page;

	/* all memory attached to an ifq should be uniform. */
	/* enforce this, and use ifq properties for sync. */
	/* BUT! fragments in flagged skb need sync indication.
	 * could get ifq from uarg->ctx (currently ctx.. )
	 *   currently, uarg is embedded in ifq,
	 *   ifq is obtained from the structure
	 *
	 *   tx ubuf has uarg->ctx == skq.
	 */
	/* host memory needs sync */
	if (zctap_page_sync(di->page))
		dma_sync_single_for_cpu(rq->pdev,
					di->addr + frag_offset,
					len, DMA_FROM_DEVICE);

	page = zctap_pageptr_page(di->page);

	skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags,
			page, frag_offset, len, truesize);

#if 0
{
	skb_frag_t *frag;
	int i;

	/* open code skb_fill_page_desc so di->page is not referenced. */
	i = skb_shinfo(skb)->nr_frags;
	frag = &skb_shinfo(skb)->frags[i];

	frag->bv_page = page;
	frag->bv_offset = frag_offset;
	skb_frag_size_set(frag, len);
	skb_shinfo(skb)->nr_frags = i + 1;

	/* rest of skb_add_rx_frag */
	skb->len += len;
	skb->data_len += len;
	skb->truesize += truesize;
}
#endif

	di->page = NULL;

#if 0
	pr_err("add frag, skb:%px  pg:%px  off:%d  len:%d  sync:%d\n",
		skb, frag->bv_page, frag->bv_offset, frag->bv_len,
		zctap_page_sync(frag->bv_page));
	pr_err("bit: %lx,  %lx\n", ZCTAP_NEED_SYNC,
		(uintptr_t)frag->bv_page & ZCTAP_NEED_SYNC);
#endif

	/* uarg is only attached to skbs which have zctap fragments */
	skb_zcopy_init(skb, &rq->zctap_ifq->uarg);
}

static inline void
zctap_copy_skb_header(struct device *pdev, struct sk_buff *skb,
		      struct mlx5e_dma_info *dma_info,
		      int offset_from, u32 headlen)
{
	const void *from = page_address(dma_info->page) + offset_from;
	/* Aligning len to sizeof(long) optimizes memcpy performance */
	unsigned int len = ALIGN(headlen, sizeof(long));

	dma_sync_single_for_cpu(pdev, dma_info->addr + offset_from, len,
				DMA_FROM_DEVICE);
	skb_copy_to_linear_data(skb, from, len);
}

struct sk_buff *
mlx5e_zctap_skb_from_cqe_nonlinear(struct mlx5e_rq *rq,
				   struct mlx5_cqe64 *cqe,
				   struct mlx5e_wqe_frag_info *wi,
				   u32 cqe_bcnt)
{
	struct mlx5e_rq_frag_info *frag_info = &rq->wqe.info.arr[0];
	struct mlx5e_wqe_frag_info *head_wi = wi;
	u8 split_offset	 = rq->buff.frame0_split;
	u16 header_len	 = split_offset ? split_offset : MLX5E_RX_MAX_HEAD;
	u16 headlen	 = min_t(u32, header_len, cqe_bcnt);
	u16 frag_headlen = headlen;
	u16 byte_cnt	 = cqe_bcnt - headlen;
	struct sk_buff *skb;

	skb = napi_alloc_skb(rq->cq.napi, ALIGN(header_len, sizeof(long)));
	if (unlikely(!skb)) {
		rq->stats->buff_alloc_err++;
		return NULL;
	}

	net_prefetchw(skb->data);

	if (split_offset) {
		/* first frag is only headers, should skip this frag and
		 * assume that all of the headers already copied to the skb
		 * inline data.
		 */
		frag_info++;
		frag_headlen = 0;
		wi++;
if (0)
	pr_err("split %px @ %d, left: %d\n", skb, split_offset, byte_cnt);
	}

	while (byte_cnt) {
		u16 frag_consumed_bytes =
			min_t(u16, frag_info->frag_size - frag_headlen, byte_cnt);

		mlx5e_zctap_add_skb_frag(rq, skb, wi->di,
					 wi->offset + frag_headlen,
					 frag_consumed_bytes,
					 frag_info->frag_stride);
		byte_cnt -= frag_consumed_bytes;
		frag_headlen = 0;
		frag_info++;
		wi++;
	}

	/* copy header */
	zctap_copy_skb_header(rq->pdev, skb, head_wi->di, head_wi->offset,
			      headlen);
	/* skb linear part was allocated with headlen and aligned to long */
	skb->tail += headlen;
	skb->len  += headlen;

	return skb;
}
