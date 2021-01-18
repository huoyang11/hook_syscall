#ifndef __HOOK_H__
#define __HOOK_H__

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/unistd.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/uaccess.h> 
#include <linux/kallsyms.h> 
#include <linux/spinlock.h>
#include <linux/sysctl.h>
#include <linux/wait.h>
#include <linux/mm.h>
#include <linux/fcntl.h>
#include <linux/rtc.h>
#include <linux/poll.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/posix_types.h>
#include <linux/types.h>
#include <linux/spinlock.h>

#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/fsnotify.h>
#include <linux/personality.h>
#include <linux/security.h>
#include <linux/ima.h>
#include <linux/mount.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/file.h>
#include <linux/fcntl.h>
#include <linux/fs_struct.h>
#include <linux/posix_acl.h>
#include <linux/hash.h>
#include <linux/bitops.h>
#include <linux/init_task.h>


#include <asm/current.h>

#include "ngx_queue.h"
#include "messagepro.h"

#define MAJOR_NUM	270

#define HOOK_USER		"yh"
#define HOOK_PASSWD		"123456"

#define tablesize (sizeof(void *) * NR_syscalls)

#define objtable(o) ((o)->hook_obj_sys_call_tables)
#define srctable(o) ((o)->hook_src_sys_call_tables)
#define systable(o) ((o)->sys_call_table_addr)

#define systbcall(o,t,n) ((t)((systable(o))[n]))
#define objtbcall(o,t,n) ((t)((objtable(o))[n]))
#define srctbcall(o,t,n) ((t)((srctable(o))[n]))


struct listen_path{
	ngx_queue_t queue_node;
	char path[PATHMAX];
};

struct listen_addr{
	ngx_queue_t queue_node;
	char srcip[IPLEN];
	char objip[IPLEN];
};

#define LOGMAX	1024

struct log_data{
	ngx_queue_t queue_node;
	char addr[LOGMAX];
};

struct hook_ctx
{
	void  *hook_obj_sys_call_tables[NR_syscalls]; //hook table
	void  *hook_src_sys_call_tables[NR_syscalls];  //src table
	void **sys_call_table_addr; //system call addr
};

typedef int (*clean_fun)(ngx_queue_t*);

struct hook_data
{
	int major;
	struct class *cls;
	struct device *dev;
	struct hook_ctx hctx;

	wait_queue_head_t inq;
	
	unsigned int islogin:1;
	unsigned int iskeymod:1;
	ngx_queue_t paths;
	ngx_queue_t keywords;
	ngx_queue_t addrs;
	ngx_queue_t logs;
	spinlock_t hook_lock;
};

#endif
