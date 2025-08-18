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
	struct snapshot *(*sshot_rtn) (const struct table *, int64_t);
};

struct cursor {
	int row;
	int table;
	long long rowid;
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
	ssht =
	    kmalloc(sizeof(struct snapshot) +
		    count * table->colnum * sizeof(struct dbsc_value),
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
		new_ssht = krealloc(*ssht, sizeof(struct snapshot) +
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
	if (unlikely
	    (dbsc_value_text_init((*ssht)->data + (*ssht)->len + 1, type) != 0))
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
		if (uts_ns
		    &&
		    unlikely(ns_snapshot_ns_common
			     (&ssht, uts_ns->ns.inum, "uts") != 0))
			goto error;

		ipc_ns = tsk->nsproxy->ipc_ns;
		if (ipc_ns
		    &&
		    unlikely(ns_snapshot_ns_common
			     (&ssht, ipc_ns->ns.inum, "ipc") != 0))
			goto error;

		mnt_ns = (struct ns_common *)tsk->nsproxy->mnt_ns;
		if (mnt_ns
		    &&
		    unlikely(ns_snapshot_ns_common(&ssht, mnt_ns->inum, "mnt")
			     != 0))
			goto error;

		pid_ns = tsk->nsproxy->pid_ns_for_children;
		if (mnt_ns
		    &&
		    unlikely(ns_snapshot_ns_common
			     (&ssht, pid_ns->ns.inum, "pid") != 0))
			goto error;

		time_ns = tsk->nsproxy->time_ns;
		if (time_ns
		    &&
		    unlikely(ns_snapshot_ns_common
			     (&ssht, time_ns->ns.inum, "time") != 0))
			goto error;

		time_ns = tsk->nsproxy->time_ns_for_children;
		if (time_ns
		    &&
		    unlikely(ns_snapshot_ns_common
			     (&ssht, time_ns->ns.inum, "time") != 0))
			goto error;

		cgroup_ns = tsk->nsproxy->cgroup_ns;
		if (cgroup_ns
		    &&
		    unlikely(ns_snapshot_ns_common
			     (&ssht, cgroup_ns->ns.inum, "cgroup") != 0))
			goto error;

		user_ns = tsk->cred->user_ns;
		if (user_ns
		    &&
		    unlikely(ns_snapshot_ns_common
			     (&ssht, user_ns->ns.inum, "user") != 0))
			goto error;
	}

	for_each_net(net) {
		if (unlikely
		    (ns_snapshot_ns_common(&ssht, net->ns.inum, "net") != 0))
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

/* syscalls implementations */
static inline int osdb_cursor_check(int cursor)
{
	return cursor < 0 || cursor >= cursors_len || !cursors[cursor].reserved;
}

static inline void osdb_cursor_reset(int cursor)
{
	int table = cursors[cursor].table;

	cursors[cursor].ssht =
	    list_first_entry(&tables[table].sshts.head, struct snapshot, list);
	cursors[cursor].row = 0;
	cursors[cursor].rowid = 0;
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

	cursors[cursor].reserved = 0;

	return 0;
}

SYSCALL_DEFINE1(osdb_vtable_filter, int, cursor)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (osdb_cursor_check(cursor))
		return -EINVAL;

	osdb_cursor_reset(cursor);
	return 0;
}

SYSCALL_DEFINE1(osdb_vtable_next, int, cursor)
{
	struct cursor *p;
	struct list_head *head;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (osdb_cursor_check(cursor))
		return -EINVAL;

	p = cursors + cursor;

	if (list_entry_is_head(p->ssht, head, list))
		return 0;

	p->row += tables[p->table].colnum;
	if (p->ssht->len <= p->row) {
		p->row = 0;
		head = &tables[p->table].sshts.head;
		p->ssht = list_next_entry(p->ssht, list);

		if (!list_entry_is_head(p->ssht, head, list))
			++p->rowid;
	} else {
		++p->rowid;
	}

	return 0;
}

SYSCALL_DEFINE1(osdb_vtable_eof, int, cursor)
{
	struct cursor *p;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (osdb_cursor_check(cursor))
		return -EINVAL;

	p = cursors + cursor;

	return list_entry_is_head(p->ssht, &tables[p->table].sshts.head, list);
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

SYSCALL_DEFINE4(osdb_vtable_column_ptr, int, cursor, int, column,
		char __user *, buf, int, size)
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

SYSCALL_DEFINE1(osdb_vtable_rowid, int, cursor)
{
	struct cursor *p;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (osdb_cursor_check(cursor))
		return -EINVAL;

	p = cursors + cursor;

	return p->rowid;
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
