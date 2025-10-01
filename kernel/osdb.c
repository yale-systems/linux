#include <linux/bitmap.h>
#include <linux/errno.h>
#include <linux/gfp_types.h>
#include <net/net_namespace.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/cgroup.h>
#include <linux/ipc_namespace.h>
#include <linux/net_namespace.h>
#include <linux/time_namespace.h>
#include <linux/utsname.h>
#include <linux/ns_common.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/tty.h>
#include <linux/types.h>
#include <uapi/linux/osdb.h>

#define MAX_CURSORS 5

struct snapshot {
	struct list_head list;
	int64_t timestamp;
	int len;
	int cap;
	struct dbsc_value data[];
};

struct snapshots {
	struct list_head head;
	int len;
};

struct table {
	int id;
	int colnum;
	struct snapshots sshts;
	void (*lock)(void);
	void (*unlock)(void);
	struct snapshot *(*sshot_rtn)(const struct table *, int64_t);
};

enum filter_op_t {
	FILTER_EQ,
	FILTER_GE,
	FILTER_GT,
	FILTER_LT,
	FILTER_LE,
};

struct condition {
	int column;
	enum filter_op_t op;
};

struct filter {
	struct condition *cond;
	struct dbsc_value *values;
	int len;
};

struct cursor {
	int row;
	struct filter filter;
	int table;
	int64_t rowid;
	int reserved;
	struct snapshot *ssht;
};

/* OSDB value functions */
static void dbsc_value_int_init(struct dbsc_value *value, int64_t val)
{
	value->type = DBSC_INT64;
	value->size = sizeof(val);
	value->int64_value = val;
}

static int dbsc_value_text_init(struct dbsc_value *value, const char *text)
{
	size_t n = strlen(text) + 1;

	value->text_value = kmalloc(n, GFP_KERNEL);
	if (unlikely(value->text_value == NULL))
		return 1;

	value->type = DBSC_TEXT;
	value->size = n;
	strcpy(value->text_value, text);

	return 0;
}

static void dbsc_value_null_init(struct dbsc_value *value)
{
	value->type = DBSC_NULL;
	value->size = sizeof(NULL);
	value->ptr_value = NULL;
}

static void dbsc_value_free(struct dbsc_value *value)
{
	if (value->type == DBSC_TEXT)
		kfree(value->text_value);
}

static int dbsc_value_eq(const struct dbsc_value *a, const struct dbsc_value *b)
{
	if (a->type != b->type)
		return 0;

	switch (a->type) {
	case DBSC_BOOLEAN:
	case DBSC_INT32:
		return a->int32_value == b->int32_value;

	case DBSC_INT64:
		return a->int64_value == b->int64_value;

	case DBSC_TEXT:
		return strcmp(a->text_value, b->text_value) == 0;

	default:
		return 0;
	}
}

static int dbsc_value_ge(const struct dbsc_value *a, const struct dbsc_value *b)
{
	if (a->type != b->type)
		return 0;

	switch (a->type) {
	case DBSC_BOOLEAN:
	case DBSC_INT32:
		return a->int32_value >= b->int32_value;

	case DBSC_INT64:
		return a->int64_value >= b->int64_value;

	case DBSC_TEXT:
		return strcmp(a->text_value, b->text_value) >= 0;

	default:
		return 0;
	}
}

static int dbsc_value_gt(const struct dbsc_value *a, const struct dbsc_value *b)
{
	if (a->type != b->type)
		return 0;

	switch (a->type) {
	case DBSC_BOOLEAN:
	case DBSC_INT32:
		return a->int32_value > b->int32_value;

	case DBSC_INT64:
		return a->int64_value > b->int64_value;

	case DBSC_TEXT:
		return strcmp(a->text_value, b->text_value) > 0;

	default:
		return 0;
	}
}

static int dbsc_value_le(const struct dbsc_value *a, const struct dbsc_value *b)
{
	if (a->type != b->type)
		return 0;

	switch (a->type) {
	case DBSC_BOOLEAN:
	case DBSC_INT32:
		return a->int32_value < b->int32_value;

	case DBSC_INT64:
		return a->int64_value < b->int64_value;

	case DBSC_TEXT:
		return strcmp(a->text_value, b->text_value) < 0;

	default:
		return 0;
	}
}

static int dbsc_value_lt(const struct dbsc_value *a, const struct dbsc_value *b)
{
	if (a->type != b->type)
		return 0;

	switch (a->type) {
	case DBSC_BOOLEAN:
	case DBSC_INT32:
		return a->int32_value <= b->int32_value;

	case DBSC_INT64:
		return a->int64_value <= b->int64_value;

	case DBSC_TEXT:
		return strcmp(a->text_value, b->text_value) <= 0;

	default:
		return 0;
	}
}

/* snapshot function */
static void snapshot_free(struct snapshot *ssht)
{
	for (int i = 0; i < ssht->len; ++i)
		dbsc_value_free(ssht->data + i);
	kfree(ssht);
}

static void process_lock(void);
static struct snapshot *process_snapshot(const struct table *table,
					 int64_t timestamp);
static void process_unlock(void);
static void ns_lock(void);
static struct snapshot *ns_snapshot(const struct table *table,
				    int64_t timestamp);
static void ns_unlock(void);

static struct table tables[] = {
	{.id = OSDB_PROCESS,
	 .colnum = 15,
	 .lock = process_lock,
	 .unlock = process_unlock,
	 .sshts = {
		   .len = 0,
		   .head = LIST_HEAD_INIT(tables[0].sshts.head),
		   },
	 .sshot_rtn = process_snapshot},
	{.id = OSDB_NS,
	 .colnum = 2,
	 .sshts = {
		   .len = 0,
		   .head = LIST_HEAD_INIT(tables[1].sshts.head),
		   },
	 .lock = ns_lock,
	 .unlock = ns_unlock,
	 .sshot_rtn = ns_snapshot},
};

static int tables_len = sizeof(tables) / sizeof(struct table);
static const int cursors_len = MAX_CURSORS;
static struct cursor cursors[MAX_CURSORS] = { 0 };

static const int max_snapshots = 5;

/* Process routines */
static void process_lock(void)
{
	rcu_read_lock();
}

static inline void add_namespace(struct dbsc_value *value,
				 const struct ns_common *ns)
{
	if (ns)
		dbsc_value_int_init(value, ns->inum);
	else
		dbsc_value_null_init(value);
}

static inline int process_snapshot_task(struct snapshot *ssht,
					struct task_struct *tsk)
{
	char name[TASK_COMM_LEN];
	char *state = NULL;
	int err;

	/* Recording the pid */
	dbsc_value_int_init(ssht->data + ssht->len, task_pid_nr(tsk));
	++ssht->len;

	/* Recording the euid */
	dbsc_value_int_init(ssht->data + ssht->len, tsk->cred->euid.val);
	++ssht->len;

	/* Recording the gid */
	dbsc_value_int_init(ssht->data + ssht->len,
			    pid_nr(get_task_pid(tsk, PIDTYPE_PGID)));
	++ssht->len;

	/* Recording the name */
	get_task_comm(name, tsk);
	err = dbsc_value_text_init(ssht->data + ssht->len, name);
	if (unlikely(err))
		return 1;
	++ssht->len;

	/* Recording the tty */
	if (tsk->signal->tty) {
		err = dbsc_value_text_init(ssht->data + ssht->len,
					   tty_name(tsk->signal->tty));
		if (unlikely(err))
			return 1;
	} else {
		dbsc_value_null_init(ssht->data + ssht->len);
	}
	++ssht->len;

	/* Recording the state */
	switch (tsk->__state) {
	case TASK_UNINTERRUPTIBLE:
	case TASK_INTERRUPTIBLE:
		state = "WAITING";
		break;
	case TASK_STOPPED:
		state = "STOPPED";
		break;
	case TASK_TRACED:
		state = "TRACED";
		break;
	case TASK_RUNNING:
		state = "RUNNING";
		break;
	}

	if (state) {
		err = dbsc_value_text_init(ssht->data + ssht->len, state);
		if (unlikely(err))
			return 1;
	} else {
		dbsc_value_null_init(ssht->data + ssht->len);
	}
	++ssht->len;

	/* Recording the ppid */
	if (tsk->parent)
		dbsc_value_int_init(ssht->data + ssht->len,
				    task_pid_nr(tsk->parent));
	else
		dbsc_value_null_init(ssht->data + ssht->len);
	++ssht->len;

	/* Recording the namespaces */
	if (tsk->nsproxy) {
		add_namespace(ssht->data + ssht->len,
			      &tsk->nsproxy->uts_ns->ns);
		add_namespace(ssht->data + ssht->len + 1,
			      &tsk->nsproxy->ipc_ns->ns);
		add_namespace(ssht->data + ssht->len + 2,
			      (struct ns_common *)tsk->nsproxy->mnt_ns);
		add_namespace(ssht->data + ssht->len + 3,
			      &tsk->nsproxy->pid_ns_for_children->ns);
		add_namespace(ssht->data + ssht->len + 4,
			      &tsk->nsproxy->time_ns->ns);
		add_namespace(ssht->data + ssht->len + 5,
			      &tsk->nsproxy->cgroup_ns->ns);
		add_namespace(ssht->data + ssht->len + 6,
			      &tsk->nsproxy->net_ns->ns);
	} else {
		for (int i = 0; i < 7; ++i)
			dbsc_value_null_init(ssht->data + ssht->len + i);
	}
	add_namespace(ssht->data + ssht->len + 7, &tsk->cred->user_ns->ns);
	ssht->len += 8;

	return 0;
}

static struct snapshot *process_snapshot(const struct table *table,
					 int64_t timestamp)
{
	unsigned long *bitset;
	struct task_struct *tsk;
	unsigned count = 0;
	pid_t pid;
	struct snapshot *ssht;

	bitset = bitmap_alloc(PID_MAX_LIMIT + 1, GFP_KERNEL);
	if (unlikely(bitset == NULL))
		return NULL;

	bitmap_zero(bitset, PID_MAX_LIMIT + 1);
	for_each_process(tsk) {
		pid = task_pid_nr(tsk);
		if (!test_bit(pid, bitset)) {
			set_bit(pid, bitset);
			++count;
		}
	}

	bitmap_zero(bitset, PID_MAX_LIMIT + 1);
	ssht = kmalloc(sizeof(struct snapshot) +
			       count * table->colnum *
				       sizeof(struct dbsc_value),
		       GFP_KERNEL);
	if (unlikely(ssht == NULL))
		goto end;

	ssht->cap = count * table->colnum;
	ssht->len = 0;

	for_each_process(tsk) {
		pid = task_pid_nr(tsk);

		if (test_bit(pid, bitset))
			continue;

		set_bit(pid, bitset);
		if (unlikely(process_snapshot_task(ssht, tsk)))
			goto error;
	}

	ssht->timestamp = timestamp;

end:
	bitmap_free(bitset);
	return ssht;

error:
	snapshot_free(ssht);
	bitmap_free(bitset);
	return NULL;
}

static void process_unlock(void)
{
	rcu_read_unlock();
}

/* Namespace routines */
static void ns_lock(void)
{
}

static int ns_snapshot_ns_common(struct snapshot **ssht, unsigned int inum,
				 const char *type)
{
	size_t i, new_cap;
	struct snapshot *new_ssht;

	for (i = 0; i < (*ssht)->len; i += 2)
		if ((*ssht)->data[i].int64_value == inum)
			return 0;

	if ((*ssht)->len == (*ssht)->cap) {
		new_cap = (*ssht)->cap * 2;
		new_ssht = krealloc(*ssht,
				    sizeof(struct snapshot) +
					    new_cap * sizeof(struct dbsc_value),
				    GFP_KERNEL);
		if (unlikely(new_ssht == NULL))
			return 1;

		new_ssht->cap = new_cap;
		*ssht = new_ssht;
	}

	/* Recording the inum */
	dbsc_value_int_init((*ssht)->data + (*ssht)->len, inum);

	/* Recording the type */
	if (unlikely(dbsc_value_text_init((*ssht)->data + (*ssht)->len + 1,
					  type) != 0))
		return 1;
	(*ssht)->len += 2;

	return 0;
}

static struct snapshot *ns_snapshot(const struct table *table,
				    int64_t timestamp)
{
	struct net *net;
	struct task_struct *tsk;
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct ns_common *mnt_ns;
	struct pid_namespace *pid_ns;
	struct time_namespace *time_ns;
	struct cgroup_namespace *cgroup_ns;
	struct user_namespace *user_ns;
	struct snapshot *ssht;

	ssht = kmalloc(sizeof(struct snapshot) +
			       8 * table->colnum * sizeof(struct dbsc_value),
		       GFP_KERNEL);
	if (unlikely(ssht == NULL))
		return NULL;

	ssht->cap = 8 * table->colnum;
	ssht->len = 0;

	for_each_process(tsk) {
		if (!tsk->nsproxy)
			continue;

		uts_ns = tsk->nsproxy->uts_ns;
		if (uts_ns &&
		    unlikely(ns_snapshot_ns_common(&ssht, uts_ns->ns.inum,
						   "uts") != 0))
			goto error;

		ipc_ns = tsk->nsproxy->ipc_ns;
		if (ipc_ns &&
		    unlikely(ns_snapshot_ns_common(&ssht, ipc_ns->ns.inum,
						   "ipc") != 0))
			goto error;

		mnt_ns = (struct ns_common *)tsk->nsproxy->mnt_ns;
		if (mnt_ns &&
		    unlikely(ns_snapshot_ns_common(&ssht, mnt_ns->inum,
						   "mnt") != 0))
			goto error;

		pid_ns = tsk->nsproxy->pid_ns_for_children;
		if (mnt_ns &&
		    unlikely(ns_snapshot_ns_common(&ssht, pid_ns->ns.inum,
						   "pid") != 0))
			goto error;

		time_ns = tsk->nsproxy->time_ns;
		if (time_ns &&
		    unlikely(ns_snapshot_ns_common(&ssht, time_ns->ns.inum,
						   "time") != 0))
			goto error;

		time_ns = tsk->nsproxy->time_ns_for_children;
		if (time_ns &&
		    unlikely(ns_snapshot_ns_common(&ssht, time_ns->ns.inum,
						   "time") != 0))
			goto error;

		cgroup_ns = tsk->nsproxy->cgroup_ns;
		if (cgroup_ns &&
		    unlikely(ns_snapshot_ns_common(&ssht, cgroup_ns->ns.inum,
						   "cgroup") != 0))
			goto error;

		user_ns = tsk->cred->user_ns;
		if (user_ns &&
		    unlikely(ns_snapshot_ns_common(&ssht, user_ns->ns.inum,
						   "user") != 0))
			goto error;
	}

	for_each_net(net) {
		if (unlikely(ns_snapshot_ns_common(&ssht, net->ns.inum,
						   "net") != 0))
			goto error;
	}

	ssht->timestamp = timestamp;
	return ssht;

error:
	snapshot_free(ssht);
	return NULL;
}

static void ns_unlock(void)
{
}

/* Snapshot queue routines */
static void snapshots_dequeue(struct snapshots *sshts)
{
	struct snapshot *head;

	head = list_first_entry(&sshts->head, struct snapshot, list);
	list_del(&head->list);
	--sshts->len;
	snapshot_free(head);
}

static inline void snapshots_enqueue(struct snapshots *sshts,
				     struct snapshot *ssht)
{
	list_add_tail(&ssht->list, &sshts->head);
	++sshts->len;
}

/* filter routines */
static int filter_init(struct filter *filter, const char *ops, int len,
		       struct dbsc_value *values)
{
	struct condition *cond;

	cond = kmalloc(sizeof(struct condition) * len, GFP_KERNEL);
	if (cond == NULL)
		return -ENOMEM;

	for (int i = 0; i < len; ++i) {
		enum filter_op_t op;
		int column = 0;

		if (strncmp(ops, "EQ", 2) == 0)
			op = FILTER_EQ;
		else if (strncmp(ops, "GE", 2) == 0)
			op = FILTER_GE;
		else if (strncmp(ops, "GT", 2) == 0)
			op = FILTER_GT;
		else if (strncmp(ops, "LE", 2) == 0)
			op = FILTER_LE;
		else if (strncmp(ops, "LT", 2) == 0)
			op = FILTER_LT;
		else
			goto error;

		ops += 2;
		if (*ops != ':')
			goto error;
		++ops;

		if (!isdigit(*ops))
			goto error;

		for (; isdigit(*ops); ++ops)
			column = 10 * column + *ops - '0';
		if (*ops == ',')
			++ops;

		cond[i].op = op;
		cond[i].column = column;
	}

	if (*ops != '\0')
		goto error;

	filter->cond = cond;
	filter->values = values;
	filter->len = len;
	return 0;

error:
	kfree(cond);
	return -EINVAL;
}

static void filter_free(struct filter *filter)
{
	for (int i = 0; i < filter->len; ++i)
		dbsc_value_free(filter->values + i);

	kfree(filter->values);
	kfree(filter->cond);
	filter->cond = NULL;
	filter->values = NULL;
	filter->len = 0;
}

static int filter_match(struct filter *filter, struct cursor *cursor)
{
	int match = 1;
	static struct dbsc_value timestamp = {
		.type = DBSC_INT64,
		.size = sizeof(int64_t),
	};
	int column;

	for (int i = 0; i < filter->len; ++i) {
		const struct dbsc_value *value;
		column = filter->cond[i].column;

		if (tables[cursor->table].colnum == column) {
			timestamp.int64_value = cursor->ssht->timestamp;
			value = &timestamp;
		} else {
			value = cursor->ssht->data + cursor->row + column;
		}

		switch (filter->cond[i].op) {
		case FILTER_EQ:
			match = dbsc_value_eq(value, filter->values + i);
			break;

		case FILTER_GE:
			match = dbsc_value_ge(value, filter->values + i);
			break;

		case FILTER_GT:
			match = dbsc_value_gt(value, filter->values + i);
			break;

		case FILTER_LE:
			match = dbsc_value_le(value, filter->values + i);
			break;

		case FILTER_LT:
			match = dbsc_value_lt(value, filter->values + i);
			return 1;
			break;
		}

		if (!match)
			break;
	}

	return match;
}

/* Cursor routines */
static inline int osdb_cursor_check(int cursor)
{
	return cursor < 0 || cursor >= cursors_len || !cursors[cursor].reserved;
}

static inline void osdb_cursor_reset(int cursor)
{
	int table = cursors[cursor].table;

	cursors[cursor].ssht = list_first_entry(&tables[table].sshts.head,
						struct snapshot, list);
	cursors[cursor].row = 0;
	cursors[cursor].rowid = 0;
}

static inline int osdb_cursor_end(struct cursor *cursor)
{
	struct list_head *head = &tables[cursor->table].sshts.head;

	return list_entry_is_head(cursor->ssht, head, list);
}

static void osdb_cursor_next(struct cursor *cursor)
{
	if (osdb_cursor_end(cursor))
		return;

	cursor->row += tables[cursor->table].colnum;
	if (cursor->ssht->len <= cursor->row) {
		cursor->row = 0;
		cursor->ssht = list_next_entry(cursor->ssht, list);

		if (!osdb_cursor_end(cursor))
			++cursor->rowid;
	} else {
		++cursor->rowid;
	}
}

static void osdb_cursor_advance(struct cursor *cursor)
{
	while (!osdb_cursor_end(cursor)) {
		if (filter_match(&cursor->filter, cursor))
			break;

		osdb_cursor_next(cursor);
	}
}

SYSCALL_DEFINE1(osdb_vtable_open, int, table)
{
	int i, cur;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	for (i = 0; i < tables_len; ++i)
		if (table == tables[i].id)
			break;

	if (i == tables_len)
		return -EINVAL;

	for (cur = 0; cur < cursors_len; ++cur)
		if (!cursors[cur].reserved)
			break;

	if (cur == cursors_len)
		return -ENOMEM;

	cursors[cur].reserved = 1;
	cursors[cur].table = i;
	osdb_cursor_reset(cur);

	return cur;
}

SYSCALL_DEFINE1(osdb_vtable_close, int, cursor)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (osdb_cursor_check(cursor))
		return -EINVAL;

	if (cursors[cursor].filter.cond != NULL)
		filter_free(&cursors[cursor].filter);
	cursors[cursor].reserved = 0;

	return 0;
}

SYSCALL_DEFINE5(osdb_vtable_filter, int, cursor, const char __user *, filter,
		int, len, int, argc, struct dbsc_value __user *, argv)
{
	struct cursor *p;
	char *kfilter;
	struct dbsc_value *kargv;
	int err = 0;
	int i;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	else if (osdb_cursor_check(cursor) || argc < 0 || len < 0) {
		return -EINVAL;
	}

	p = cursors + cursor;
	if (p->filter.len != 0)
		filter_free(&p->filter);

	if (!access_ok(filter, len)) {
		return -EFAULT;
	} else if (!access_ok(argv, sizeof(struct dbsc_value *) * argc)) {
		return -EFAULT;
	}

	if (len == 0)
		goto out;

	kfilter = kmalloc(len + 1, GFP_KERNEL);
	if (kfilter == NULL) {
		return -ENOMEM;
	}

	if (strncpy_from_user(kfilter, filter, len + 1) != len) {
		err = -EFAULT;
		goto kfilter_cleanup;
	}

	kargv = kmalloc(argc * sizeof(struct dbsc_value), GFP_KERNEL);
	if (!kargv) {
		err = -ENOMEM;
		goto kfilter_cleanup;
	}

	if (copy_from_user(kargv, argv, sizeof(struct dbsc_value) * argc)) {
		err = -EFAULT;
		goto kargv_cleanup;
	}

	for (i = 0; i < argc; ++i) {
		char *text_value;
		if (kargv[i].type != DBSC_TEXT)
			continue;

		text_value = strndup_user(kargv[i].text_value, kargv[i].size);
		if (text_value == NULL) {
			err = -ENOMEM;
			goto kargv_text_cleanup;
		}

		kargv[i].text_value = text_value;
	}

	err = filter_init(&p->filter, kfilter, argc, kargv);
	if (err != 0)
		goto kargv_text_cleanup;

	kfree(kfilter);

out:
	osdb_cursor_reset(cursor);
	osdb_cursor_advance(cursors + cursor);
	return err;

kargv_text_cleanup:
	for (int j = 0; j < i; ++j)
		dbsc_value_free(kargv + j);

kargv_cleanup:
	kfree(kargv);

kfilter_cleanup:
	kfree(kfilter);

	return err;
}

SYSCALL_DEFINE1(osdb_vtable_next, int, cursor)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (osdb_cursor_check(cursor))
		return -EINVAL;

	osdb_cursor_next(cursors + cursor);
	osdb_cursor_advance(cursors + cursor);

	return 0;
}

SYSCALL_DEFINE1(osdb_vtable_eof, int, cursor)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (osdb_cursor_check(cursor))
		return -EINVAL;

	return osdb_cursor_end(cursors + cursor);
}

SYSCALL_DEFINE3(osdb_vtable_column, int, cursor, int, column,
		struct dbsc_value __user *, out)
{
	struct cursor *p;
	static struct dbsc_value timestamp = {
		.type = DBSC_INT64,
		.size = sizeof(int64_t),
	};
	struct dbsc_value *value;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	else if (!access_ok(out, sizeof(struct dbsc_value)))
		return -EFAULT;
	else if (osdb_cursor_check(cursor))
		return -EINVAL;

	p = cursors + cursor;
	if (column > tables[p->table].colnum) {
		return -EINVAL;
	} else if (tables[p->table].colnum == column) {
		timestamp.int64_value = p->ssht->timestamp;
		value = &timestamp;
	} else {
		value = p->ssht->data + p->row + column;
	}

	if (copy_to_user(out, value, sizeof(struct dbsc_value)))
		return -EFAULT;

	return 0;
}

SYSCALL_DEFINE4(osdb_vtable_column_ptr, int, cursor, int, column, char __user *,
		buf, int, size)
{
	struct cursor *p;
	struct dbsc_value *out;
	int len;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	else if (!access_ok(buf, size))
		return -EFAULT;
	else if (osdb_cursor_check(cursor))
		return -EINVAL;

	p = cursors + cursor;
	if (column >= tables[p->table].colnum)
		return -EINVAL;

	out = p->ssht->data + p->row + column;
	len = size < out->size ? size : out->size;
	if (copy_to_user(buf, out->text_value, len))
		return -EFAULT;

	return 0;
}

SYSCALL_DEFINE2(osdb_vtable_rowid, int, cursor, int64_t __user *, rowid)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (osdb_cursor_check(cursor))
		return -EINVAL;

	if (copy_to_user(rowid, &cursors[cursor].rowid, sizeof(int64_t)))
		return -EFAULT;

	return 0;
}

SYSCALL_DEFINE2(osdb_snapshot, int, flags, long long, timestamp)
{
	struct snapshot *ssht;
	int ret = 0;

	for (int i = 0; i < tables_len; ++i) {
		if (!(tables[i].id & flags))
			continue;

		tables[i].lock();
	}

	for (int i = 0; i < tables_len; ++i) {
		if (!(tables[i].id & flags))
			continue;

		ssht = tables[i].sshot_rtn(tables + i, timestamp);
		if (unlikely(ssht == NULL)) {
			ret = -ENOMEM;
			break;
		}

		if (ssht->len == 0) {
			kfree(ssht);
			continue;
		}

		if (tables[i].sshts.len == max_snapshots)
			snapshots_dequeue(&tables[i].sshts);

		snapshots_enqueue(&tables[i].sshts, ssht);
	}

	for (int i = 0; i < tables_len; ++i) {
		if (!(tables[i].id & flags))
			continue;

		tables[i].unlock();
	}

	return ret;
}

SYSCALL_DEFINE1(osdb_snapshot_clear, int, flags)
{
	for (int i = 0; i < tables_len; ++i) {
		if (!(tables[i].id & flags))
			continue;

		while (tables[i].sshts.len > 0)
			snapshots_dequeue(&tables[i].sshts);
	}

	for (int i = 0; i < cursors_len; ++i) {
		if (!cursors[i].reserved || !(cursors[i].table & flags))
			continue;

		osdb_cursor_reset(i);
	}

	return 0;
}
