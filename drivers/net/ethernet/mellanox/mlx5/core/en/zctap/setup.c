#include "en.h"
#include "en/xdp.h"
#include "en/params.h"
#include "en/zctap/setup.h"

struct zctap_ifq *
mlx5e_zctap_get_ifq(struct mlx5e_params *params, struct mlx5e_xsk *xsk,
		     u16 ix)
{
	if (!xsk || !xsk->ifq_tbl)
		return NULL;

	if (unlikely(ix >= params->num_channels))
		return NULL;

	if (unlikely(xsk->is_pool))
		return NULL;

	return xsk->ifq_tbl[ix];
}

static int mlx5e_zctap_get_tbl(struct mlx5e_xsk *xsk)
{
	if (!xsk->ifq_tbl) {
		xsk->ifq_tbl = kcalloc(MLX5E_MAX_NUM_CHANNELS,
				       sizeof(*xsk->ifq_tbl), GFP_KERNEL);
		if (unlikely(!xsk->ifq_tbl))
			return -ENOMEM;
		xsk->is_pool = false;
	}
	if (xsk->is_pool)
		return -EINVAL;

	xsk->refcnt++;
	xsk->ever_used = true;

	return 0;
}

static void mlx5e_zctap_put_tbl(struct mlx5e_xsk *xsk)
{
	if (!--xsk->refcnt) {
		kfree(xsk->ifq_tbl);
		xsk->ifq_tbl = NULL;
	}
}

static void mlx5e_zctap_remove_ifq(struct mlx5e_xsk *xsk, u16 ix)
{
	xsk->ifq_tbl[ix] = NULL;

	mlx5e_zctap_put_tbl(xsk);
}

static int mlx5e_zctap_add_ifq(struct mlx5e_xsk *xsk, struct zctap_ifq *ifq,
				u16 ix)
{
	int err;

	err = mlx5e_zctap_get_tbl(xsk);
	if (unlikely(err))
		return err;

	xsk->ifq_tbl[ix] = ifq;

	return 0;
}

static u16
mlx5e_zctap_find_unused_ifq(struct mlx5e_priv *priv,
			     struct mlx5e_params *params)
{
	u16 ix;

	for (ix = 0; ix < params->num_channels; ix++) {
		if (!mlx5e_zctap_get_ifq(params, &priv->xsk, ix))
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

	u32 rqtn = priv->xsk_tir[ix].rqt.rqtn;

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

int mlx5e_zctap_redirect_rqts_to_channels(struct mlx5e_priv *priv,
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

void mlx5e_zctap_redirect_rqts_to_drop(struct mlx5e_priv *priv,
					struct mlx5e_channels *chs)
{
	int i;

	for (i = 0; i < chs->num; i++) {
		if (!test_bit(MLX5E_CHANNEL_STATE_ZCTAP, chs->c[i]->state))
			continue;

		mlx5e_zctap_redirect_rqt_to_drop(priv, i);
	}
}

static void mlx5e_activate_zctap(struct mlx5e_channel *c)
{
	set_bit(MLX5E_RQ_STATE_ENABLED, &c->xskrq.state);

	spin_lock(&c->async_icosq_lock);
	mlx5e_trigger_irq(&c->async_icosq);
	spin_unlock(&c->async_icosq_lock);
}

void mlx5e_deactivate_zctap(struct mlx5e_channel *c)
{
	mlx5e_deactivate_rq(&c->xskrq);
}

static int mlx5e_zctap_enable_locked(struct mlx5e_priv *priv,
				      struct zctap_ifq *ifq, u16 *qid)
{
	struct mlx5e_params *params = &priv->channels.params;
	struct mlx5e_channel *c;
	int err;
	u16 ix;

	if (*qid == (u16)-1) {
		ix = mlx5e_zctap_find_unused_ifq(priv, params);
		if (ix >= params->num_channels)
			return -EBUSY;

		mlx5e_get_qid_for_ch_in_group(params, qid, ix,
					      MLX5E_RQ_GROUP_XSK);
	} else {
		if (!mlx5e_qid_get_ch_if_in_group(params, *qid,
						  MLX5E_RQ_GROUP_XSK, &ix))
			return -EINVAL;

		if (unlikely(mlx5e_zctap_get_ifq(params, &priv->xsk, ix)))
			return -EBUSY;
	}

	err = mlx5e_zctap_add_ifq(&priv->xsk, ifq, ix);
	if (unlikely(err))
		return err;

	if (!test_bit(MLX5E_STATE_OPENED, &priv->state))
		goto validate_closed;

	c = priv->channels.c[ix];

	err = mlx5e_open_zctap(priv, params, ifq, c);
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
	mlx5e_zctap_remove_ifq(&priv->xsk, ix);

	return err;

validate_closed:
	return 0;
}

static int mlx5e_zctap_disable_locked(struct mlx5e_priv *priv, u16 *qid)
{
	struct mlx5e_params *params = &priv->channels.params;
	struct mlx5e_channel *c;
	struct zctap_ifq *ifq;
	u16 ix;

	if (unlikely(!mlx5e_qid_get_ch_if_in_group(params, *qid,
						   MLX5E_RQ_GROUP_XSK, &ix)))
		return -EINVAL;

	ifq = mlx5e_zctap_get_ifq(params, &priv->xsk, ix);

	if (unlikely(!ifq))
		return -EINVAL;

	if (!test_bit(MLX5E_STATE_OPENED, &priv->state))
		goto remove_ifq;

	c = priv->channels.c[ix];
	mlx5e_zctap_redirect_rqt_to_drop(priv, ix);
	mlx5e_deactivate_zctap(c);
	mlx5e_close_zctap(c);

remove_ifq:
	mlx5e_zctap_remove_ifq(&priv->xsk, ix);

	return 0;
}

static int mlx5e_zctap_enable_ifq(struct mlx5e_priv *priv,
				   struct zctap_ifq *ifq, u16 *qid)
{
	int err;

	mutex_lock(&priv->state_lock);
	err = mlx5e_zctap_enable_locked(priv, ifq, qid);
	mutex_unlock(&priv->state_lock);

	return err;
}

static int mlx5e_zctap_disable_ifq(struct mlx5e_priv *priv, u16 *qid)
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

int mlx5e_open_zctap(struct mlx5e_priv *priv, struct mlx5e_params *params,
		      struct zctap_ifq *ifq, struct mlx5e_channel *c)
{
	struct mlx5e_xsk_param xsk = { .hd_split = ifq->split_offset };
	struct mlx5e_channel_param *cparam;
	struct mlx5e_create_cq_param ccp;
	int err;

        mlx5e_build_create_cq_param(&ccp, c);

	cparam = kvzalloc(sizeof(*cparam), GFP_KERNEL);
	if (!cparam)
		return -ENOMEM;

	mlx5e_build_rq_param(priv, params, &xsk, &cparam->rq);

	err = mlx5e_open_cq(c->priv, params->rx_cq_moderation, &cparam->rq.cqp,
			    &ccp, &c->xskrq.cq);
	if (unlikely(err))
		goto err_free_cparam;

	err = mlx5e_open_rq(c, params, &cparam->rq, &xsk, NULL, &c->xskrq);
	if (unlikely(err))
		goto err_close_rx_cq;
	c->xskrq.zctap_ifq = ifq;

	kvfree(cparam);

	set_bit(MLX5E_CHANNEL_STATE_ZCTAP, c->state);

	return 0;

err_close_rx_cq:
	mlx5e_close_cq(&c->xskrq.cq);

err_free_cparam:
	kvfree(cparam);

	return err;
}

void mlx5e_close_zctap(struct mlx5e_channel *c)
{
	clear_bit(MLX5E_CHANNEL_STATE_ZCTAP, c->state);
	napi_synchronize(&c->napi);
	synchronize_rcu(); /* Sync with the XSK wakeup. */

	mlx5e_close_rq(&c->xskrq);
	mlx5e_close_cq(&c->xskrq.cq);

	memset(&c->xskrq, 0, sizeof(c->xskrq));
}
