#include <linux/bitmap.h>
#include <linux/errno.h>
#include <linux/gfp_types.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/tty.h>
#include <linux/types.h>
#include <uapi/linux/osdb.h>

#define MAX_CURSORS 5

struct snapshot {
	struct list_head list;
    ktime_t timestamp;
    int len;
    int cap;
    struct osdb_value data[];
};

struct snapshots {
    struct list_head head;
    int len;
};

struct table {
	int id;
	int enabled;
    int colnum;
	struct snapshots sshts;
	void (*lock)(void);
    void (*unlock)(void);
    struct snapshot *(*sshot_rtn)(ktime_t);
};

struct cursor {
	int row;
	int table;
	long long rowid;
    int reserved;
    struct snapshot *ssht;
};


/* OSDB value functions */
static void osdb_value_int_init(struct osdb_value *value, int64_t val)
{
	value->type = OSDB_VALUE_INT;
    value->len = sizeof(val);
	value->int_value = val;
}

static int osdb_value_text_init(struct osdb_value *value, const char *text)
{
	size_t n = strlen(text) + 1;

	value->ptr_value = kmalloc(n, GFP_KERNEL);
	if (unlikely(value->ptr_value == NULL))
		return 1;

	value->type = OSDB_VALUE_TEXT;
    value->len = n;
    strcpy(value->ptr_value, text);

    return 0;
}

static void osdb_value_null_init(struct osdb_value *value)
{
	value->type = OSDB_VALUE_NULL;
    value->len = sizeof(NULL);
    value->ptr_value = NULL;
}

static void osdb_value_free(struct osdb_value *value)
{
	if (value->type == OSDB_VALUE_TEXT)
        kfree(value->ptr_value);
}


/* snapshot function */
static void snapshot_free(struct snapshot *ssht)
{
    for (int i = 0; i < ssht->len; ++i)
	    osdb_value_free(ssht->data + i);
    kfree(ssht);
}


/* Process routines */
static void process_lock(void)
{
    rcu_read_lock();
}

static inline int process_snapshot_task(struct snapshot *ssht, struct task_struct *tsk)
{
	char name[TASK_COMM_LEN];
    int err;

	/* Recording the pid */
    osdb_value_int_init(ssht->data + ssht->len, task_pid_nr(tsk));
    ++ssht->len;

    /* Recording the euid */
    osdb_value_int_init(ssht->data + ssht->len, tsk->cred->euid.val);
    ++ssht->len;

    /* Recording the gid */
    osdb_value_int_init(ssht->data + ssht->len,
                        pid_nr(get_task_pid(tsk, PIDTYPE_PGID)));
    ++ssht->len;
    
    /* Recording the name */
    get_task_comm(name, tsk);
    err = osdb_value_text_init(ssht->data + ssht->len, name);
    if (unlikely(err))
        return 1;
    ++ssht->len;

    /* Recording the tty */
    if (tsk->signal->tty) {
        err = osdb_value_text_init(ssht->data + ssht->len,
                                   tty_name(tsk->signal->tty));
        if (unlikely(err))
            return 1;
    } else {
        osdb_value_null_init(ssht->data + ssht->len);
    }
    ++ssht->len;

    /* Recording the ppid */
    if (tsk->parent)
        osdb_value_int_init(ssht->data + ssht->len,
                            task_pid_nr(tsk->parent));
    else
        osdb_value_null_init(ssht->data + ssht->len);
    ++ssht->len;

    return 0;
}

static struct snapshot *process_snapshot(ktime_t timestamp)
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
    ssht = kmalloc(sizeof(struct snapshot) + count*6 * sizeof(struct osdb_value), GFP_KERNEL);
    if (unlikely(ssht == NULL))
	    goto end;

    ssht->cap = count * 6;
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


static struct table tables[] = { {
        .id = OSDB_PROCESS,
        .enabled = 0,
        .colnum = 6,
        .lock = process_lock,
        .unlock = process_unlock,
        .sshot_rtn = process_snapshot
    },
};
static int tables_len = sizeof(tables) / sizeof(struct table);
static const int cursors_len = MAX_CURSORS;
static struct cursor cursors[MAX_CURSORS] = { 0 };
static const int max_snapshots = 5;


static inline void snapshots_init(struct snapshots *sshts)
{
    INIT_LIST_HEAD(&sshts->head);
    sshts->len = 0;
}

static void snapshots_dequeue(struct snapshots *sshts)
{
	struct snapshot *head;

	head = list_first_entry(&sshts->head, struct snapshot, list);
	list_del(&head->list);
    --sshts->len;
    snapshot_free(head);
}

static inline void snapshots_enqueue(struct snapshots *sshts, struct snapshot *ssht)
{
    list_add_tail(&ssht->list, &sshts->head);
    ++sshts->len;
}


/* syscalls implementations */
static int do_osdb_vtable_create(int flags)
{
    int i;

    for (i = 0; i < tables_len; ++i) {
		if (!(flags & tables[i].id)) {
			continue;
		} else if (tables[i].enabled) {
            ++tables[i].enabled;
        } else {
            snapshots_init(&tables[i].sshts);
            tables[i].enabled = 1;
        }
	}

    return 0;
}

static int do_osdb_vtable_destroy(int flags)
{
	for (int i = 0; i < tables_len; ++i) {
		if (!(flags & tables[i].id) || tables[i].enabled == 0)
			continue;

		--tables[i].enabled;
		if (--tables[i].enabled != 0)
            continue;

		while (tables[i].sshts.len > 0)
            snapshots_dequeue(&tables[i].sshts);
    }

    return 0;
}

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

SYSCALL_DEFINE1(osdb_vtable_create, int, flags)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	return do_osdb_vtable_create(flags);
}

SYSCALL_DEFINE1(osdb_vtable_connect, int, flags)
{
    if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

    return do_osdb_vtable_create(flags);
}

SYSCALL_DEFINE1(osdb_vtable_bestindex, struct osdb_vtable_bestindex_args __user *, args)
{
    return 0;
}

SYSCALL_DEFINE1(osdb_vtable_disconnect, int, flags)
{
    if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

    return do_osdb_vtable_destroy(flags);
}

SYSCALL_DEFINE1(osdb_vtable_destroy, int, flags)
{
    if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

    return do_osdb_vtable_destroy(flags);
}

SYSCALL_DEFINE1(osdb_vtable_open, int, table)
{
	int i, cur;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	for (i = 0; i < tables_len; ++i)
		if ((table & tables[i].id) && tables[i].enabled)
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
    if (p->ssht->len <= p->row) {
	    p->row = 0;
        head = &tables[p->table].sshts.head;

        do {
            p->ssht = list_next_entry(p->ssht, list);
        } while (!list_entry_is_head(p->ssht, head, list) &&
                 p->ssht->len <= p->row);

        if (!list_entry_is_head(p->ssht, head, list))
            ++p->rowid;
    } else {
	    p->row += tables[p->table].colnum;
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

SYSCALL_DEFINE1(osdb_vtable_column, struct osdb_vtable_column_args __user *, args)
{
    // TODO implement
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

SYSCALL_DEFINE1(osdb_vtable_update, struct osdb_vtable_update_args __user *, args)
{
    return 0;
}

SYSCALL_DEFINE1(osdb_vtable_snapshot, int, flags)
{
    struct snapshot *ssht;
    int ret = 0;

    for (int i = 0; i < tables_len; ++i) {
		if (!(tables[i].id & flags) || !tables[i].enabled)
			continue;

        tables[i].lock();
    }

    for (int i = 0; i < tables_len; ++i) {
		if (!(tables[i].id & flags) || !tables[i].enabled)
			continue;

		ssht = tables[i].sshot_rtn(0);
		if (unlikely(ssht == NULL)) {
            ret = -ENOMEM;
            break;
		}

		if (tables[i].sshts.len == max_snapshots)
			snapshots_dequeue(&tables[i].sshts);

		snapshots_enqueue(&tables[i].sshts, ssht);
    }

    for (int i = 0; i < tables_len; ++i) {
		if (!(tables[i].id & flags) || !tables[i].enabled)
			continue;

        tables[i].unlock();
    }

    return ret;
}
