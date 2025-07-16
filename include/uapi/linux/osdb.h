#ifndef _UAPI_LINUX_OSDB_H
#define _UAPI_LINUX_OSDB_H


#include <linux/types.h>

#define OSDB_PROCESS 0x1


enum osdb_value_tag {
	OSDB_VALUE_INT = 0x1,
	OSDB_VALUE_TEXT = 0x2,
    OSDB_VALUE_NULL = 0x3,
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
