#ifndef __MODULE_H__
#define __MODULE_H__

#define ARRLEN(a)	((sizeof(a))/(sizeof(a[0])))

typedef struct hook_module_s{
	void *ctx;
	int (*init_module)(void *);	
	int (*init_hook)(void *);
	int (*exit_hook)(void *);

	int syscallnum;
	void *hook_function;
}hook_module_t;

extern hook_module_t *hook_modules[];

#endif
