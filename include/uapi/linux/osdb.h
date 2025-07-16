#ifndef _UAPI_LINUX_OSDB_H
#define _UAPI_LINUX_OSDB_H


#include <linux/types.h>

#define OSDB_PROCESS 0x1


enum osdb_value_tag {
	OSDB_VALUE_INT,
	OSDB_VALUE_TEXT,
    OSDB_VALUE_NULL,
};

struct osdb_value {
	enum osdb_value_tag type;
    size_t len;
    union {
	    char *ptr_value;
		int64_t int_value;
    };
};


struct osdb_vtable_bestindex_args {};
struct osdb_vtable_update_args {};

#endif
