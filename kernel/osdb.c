#include <linux/syscalls.h>

SYSCALL_DEFINE1(osdb_vtable_create, struct osdb_vtable_create_args __user *, args)
{
    return 0;
}

SYSCALL_DEFINE1(osdb_vtable_connect, struct osdb_vtable_connect_args __user *, args)
{
    return 1;
}

SYSCALL_DEFINE1(osdb_vtable_bestindex, struct osdb_vtable_bestindex_args __user *, args)
{
    return 1;
}

SYSCALL_DEFINE1(osdb_vtable_disconnect, struct osdb_vtable_disconnect_args __user *, args)
{
    return 1;
}

SYSCALL_DEFINE1(osdb_vtable_destroy, struct osdb_vtable_destroy_args __user *, args)
{
    return 1;
}

SYSCALL_DEFINE1(osdb_vtable_open, struct osdb_vtable_open_args __user *, args)
{
    return 1;
}

SYSCALL_DEFINE1(osdb_vtable_close, struct osdb_vtable_close_args __user *, args)
{
    return 1;
}

SYSCALL_DEFINE1(osdb_vtable_filter, struct osdb_vtable_filter_args __user *, args)
{
    return 1;
}

SYSCALL_DEFINE1(osdb_vtable_next, struct osdb_vtable_next_args __user *, args)
{
    return 1;
}

SYSCALL_DEFINE1(osdb_vtable_eof, struct osdb_vtable_eof_args __user *, args)
{
    return 1;
}

SYSCALL_DEFINE1(osdb_vtable_column, struct osdb_vtable_column_args __user *, args)
{
    return 1;
}

SYSCALL_DEFINE1(osdb_vtable_rowid, struct osdb_vtable_rowid_args __user *, args)
{
    return 1;
}

SYSCALL_DEFINE1(osdb_vtable_update, struct osdb_vtable_update_args __user *, args)
{
    return 1;
}
