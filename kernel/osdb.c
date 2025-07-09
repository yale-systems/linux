#include <linux/errno.h>
#include <linux/syscalls.h>
#include <uapi/linux/osdb.h>
#include <linux/list.h>


#define MAX_CURSORS 5

struct snapshot {
	struct osdb_value *data;
    int size;
    int cap;
    // TODO add snapshot time
    struct list_head list;
};

struct snapshots {
    struct list_head head;
    int size;
};

struct table {
	int id;
	int enabled;
	struct snapshots sshts;
    int (*sshot_rtn)(void);
};

struct cursor {
	int row;
	int table;
	long long rowid;
    int reserved;
    struct snapshot *ssht;
};


static int process_snapshot(void)
{
    return 0;
}

// FIXME all locking logic is still missing
static struct table tables[] = { {
        .id = OSDB_PROCESS,
        .enabled = 0,
        .sshot_rtn = process_snapshot
    },
};
static int tables_len = sizeof(tables) / sizeof(struct table);
static const int cursors_len = MAX_CURSORS;
static struct cursor cursors[MAX_CURSORS] = { 0 };
static const int max_snapshots = 5;


static inline void snapshots_init(struct snapshots *snapshots)
{
    INIT_LIST_HEAD(&snapshots->head);
    snapshots->size = 0;
}

static int do_osdb_vtable_create(int flags)
{
    int i;

    for (i = 0; i < tables_len; ++i) {
		if (!(flags & tables[i].id))
			continue;
		else if (tables[i].enabled)
			continue;

		snapshots_init(&tables[i].sshts);
		tables[i].enabled = 1;
	}

    return 0;
}

static int do_osdb_vtable_destroy(int flags)
{
	for (int i = 0; i < tables_len; ++i) {
		if (!(flags & tables[i].id) || !tables[i].enabled)
			continue;

		// TODO free queue nodes
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
		if (table & tables[i].id && tables[i].enabled)
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

    return 0;
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
    if (p->ssht->size <= p->row) {
	    p->row = 0;
        head = &tables[p->table].sshts.head;

        do {
            p->ssht = list_next_entry(p->ssht, list);
        } while (!list_entry_is_head(p->ssht, head, list) &&
                 p->ssht->size <= p->row);

        if (!list_entry_is_head(p->ssht, head, list))
            ++p->rowid;
    } else {
	    ++p->row;
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
    // TODO implement
	for (int i = 0; i < tables_len; ++i) {
		if (!(tables[i].id & flags))
			continue;

        
    }

    return 0;
}
