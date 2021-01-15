#include "module.h"
#include "hook_open.h"
#include "hook_connect.h"

extern hook_module_t hook_open_module;
extern hook_module_t hook_connect_module;


hook_module_t *hook_modules[] = {
	&hook_open_module,
	&hook_connect_module,
	NULL,
};

