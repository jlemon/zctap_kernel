#ifndef _UAPI_MISC_SHQUEUE_H
#define _UAPI_MISC_SHQUEUE_H

/* Placed under UAPI in order to avoid two identical copies between
 * user and kernel space.
 */

/* user and kernel private copy - identical in order to share sq* fcns */
struct shared_queue {
	unsigned *prod;
	unsigned *cons;
	unsigned char *data;
	unsigned elt_sz;
	unsigned mask;
	unsigned cached_prod;
	unsigned cached_cons;
	unsigned entries;

	unsigned map_sz;
	void *map_ptr;
};

/*
 * see documenation in tools/include/linux/ring_buffer.h
 * using  explicit smp_/_ONCE is an optimization over smp_{store|load}
 */

static inline void __sq_load_acquire_cons(struct shared_queue *q)
{
	/* Refresh the local tail pointer */
	q->cached_cons = READ_ONCE(*q->cons);
	/* A, matches D */
}

static inline void __sq_store_release_cons(struct shared_queue *q)
{
	smp_mb(); /* D, matches A */
	WRITE_ONCE(*q->cons, q->cached_cons);
}

static inline void __sq_load_acquire_prod(struct shared_queue *q)
{
	/* Refresh the local pointer */
	q->cached_prod = READ_ONCE(*q->prod);
	smp_rmb(); /* C, matches B */
}

static inline void __sq_store_release_prod(struct shared_queue *q, unsigned v)
{
	smp_wmb(); /* B, matches C */
	WRITE_ONCE(*q->prod, v);
}

static inline void sq_cons_refresh(struct shared_queue *q)
{
	__sq_store_release_cons(q);
	__sq_load_acquire_prod(q);
}

static inline bool sq_is_empty(struct shared_queue *q)
{
	return READ_ONCE(*q->prod) == READ_ONCE(*q->cons);
}

static inline bool sq_cons_empty(struct shared_queue *q)
{
	return q->cached_prod == q->cached_cons;
}

static inline unsigned __sq_cons_ready(struct shared_queue *q)
{
	return q->cached_prod - q->cached_cons;
}

static inline unsigned sq_cons_ready(struct shared_queue *q)
{
	if (sq_cons_empty(q))
		__sq_load_acquire_prod(q);

	return __sq_cons_ready(q);
}

static inline bool sq_cons_avail(struct shared_queue *q, unsigned count)
{
	if (count <= __sq_cons_ready(q))
		return true;
	__sq_load_acquire_prod(q);
	return count <= __sq_cons_ready(q);
}

static inline void *sq_get_ptr(struct shared_queue *q, unsigned idx)
{
	return q->data + (idx & q->mask) * q->elt_sz;
}

static inline void sq_cons_complete(struct shared_queue *q)
{
	__sq_store_release_cons(q);
}

static inline void *sq_cons_peek(struct shared_queue *q)
{
	if (sq_cons_empty(q)) {
		sq_cons_refresh(q);
		if (sq_cons_empty(q))
			return NULL;
	}
	return sq_get_ptr(q, q->cached_cons);
}

static inline unsigned
sq_peek_batch(struct shared_queue *q, void **ptr, unsigned count)
{
	unsigned i, idx, ready;

	ready = sq_cons_ready(q);
	if (!ready)
		return 0;

	count = count > ready ? ready : count;

	idx = q->cached_cons;
	for (i = 0; i < count; i++)
		ptr[i] = sq_get_ptr(q, idx++);

	return count;
}

static inline unsigned
sq_cons_batch(struct shared_queue *q, void **ptr, unsigned count)
{
	unsigned i, idx, ready;

	ready = sq_cons_ready(q);
	if (!ready)
		return 0;

	count = count > ready ? ready : count;

	idx = q->cached_cons;
	for (i = 0; i < count; i++)
		ptr[i] = sq_get_ptr(q, idx++);

	q->cached_cons += count;
	sq_cons_complete(q);

	return count;
}

static inline void sq_cons_advance(struct shared_queue *q)
{
	q->cached_cons++;
}

static inline unsigned __sq_prod_space(struct shared_queue *q)
{
	return q->entries - (q->cached_prod - q->cached_cons);
}

static inline unsigned sq_prod_space(struct shared_queue *q)
{
	unsigned space;

	space = __sq_prod_space(q);
	if (!space) {
		__sq_load_acquire_cons(q);
		space = __sq_prod_space(q);
	}
	return space;
}

static inline bool sq_prod_avail(struct shared_queue *q, unsigned count)
{
	if (count <= __sq_prod_space(q))
		return true;
	__sq_load_acquire_cons(q);
	return count <= __sq_prod_space(q);
}

static inline void *sq_prod_get_ptr(struct shared_queue *q)
{
	return sq_get_ptr(q, q->cached_prod++);
}

static inline void *sq_prod_reserve(struct shared_queue *q)
{
	if (!sq_prod_space(q))
		return NULL;

	return sq_prod_get_ptr(q);
}

static inline void sq_prod_submit(struct shared_queue *q)
{
	__sq_store_release_prod(q, q->cached_prod);
}

static inline void sq_prod_submit_n(struct shared_queue *q, unsigned count)
{
	unsigned prod;

	prod = READ_ONCE(*q->prod) + count;
	if (q->cached_prod - prod < q->entries)
		__sq_store_release_prod(q, prod);
}

#endif /* _UAPI_MISC_SHQUEUE_H */
