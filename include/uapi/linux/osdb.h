#ifndef _UAPI_LINUX_OSDB_H
#define _UAPI_LINUX_OSDB_H


#include <linux/types.h>

#define OSDB_PROCESS 0x1


enum osdb_value_tag {
	OSDB_VALUE_INT,
    OSDB_VALUE_TEXT,
};

struct osdb_value {
    enum osdb_value_tag type;
    union {
	    char *ptr_value;
		int64_t int_value;
    };
};

/* struct osdb_vtable_create_args { */
/*     char name[64]; */
/* }; */

/* struct osdb_vtable_connect_args { */
/*     char name[64]; */
/* }; */

struct osdb_vtable_bestindex_args {};
//struct osdb_vtable_disconnect_args {};
//struct osdb_vtable_destroy_args {};
struct osdb_vtable_open_args {};
struct osdb_vtable_close_args {};
struct osdb_vtable_filter_args {};
struct osdb_vtable_next_args {};
struct osdb_vtable_eof_args {};
struct osdb_vtable_column_args {};
struct osdb_vtable_rowid_args {};
struct osdb_vtable_update_args {};


#endif
