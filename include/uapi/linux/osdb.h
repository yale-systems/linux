#ifndef _UAPI_LINUX_OSDB_H
#define _UAPI_LINUX_OSDB_H

#include <linux/types.h>

#define OSDB_PROCESS 0x1
#define OSDB_NS      0x2

enum dbsc_value_t {
	DBSC_BLOB = 0x1,
	DBSC_BOOLEAN = 0x2,
	DBSC_DOUBLE = 0x3,
	DBSC_NULL = 0x4,
	DBSC_INT32 = 0x5,
	DBSC_INT64 = 0x6,
	DBSC_TEXT = 0x7,
	DBSC_TEXT16 = 0x8,
};

struct dbsc_value {
	enum dbsc_value_t type;
	int size;
	union {
		char *ptr_value;
		double double_value;
		int32_t int32_value;
		int64_t int64_value;
		uint8_t *blob_value;
		char *text_value;
		char *text16_value;
	};
};

struct osdb_vtable_bestindex_args {
};
struct osdb_vtable_update_args {
};

#endif
