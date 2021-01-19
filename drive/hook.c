#include "hook.h"
#include "hook_open.h"
#include "module.h"
#include "messagepro.h"

MODULE_LICENSE("GPL"); 
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("geeksword"); 
MODULE_DESCRIPTION("hook sys_open"); 

struct hook_data *hook_dev;

static int queue_clean(ngx_queue_t *queue,clean_fun f)
{
    ngx_queue_t  *q, *next;

	if (!queue || !f) {
		return -1;
	}

	//只有头节点
    if (q == ngx_queue_last(queue)) {
        return 0;
    }
	//遍历节点
    for (q = ngx_queue_head(queue); q != ngx_queue_sentinel(queue); q = next) {
        next = ngx_queue_next(q);
		//删除当前遍历的节点
        ngx_queue_remove(q);
		f(q);
    }

	return 0;
}

static void disable_write_protect(void)
{
	write_cr0(read_cr0() & (~0x10000));
}

static void enable_write_protect(void)
{
	write_cr0(read_cr0() | 0x10000);   
}

static int obtain_sys_call_table_addr(void **sys_call_table_addr) 
{  
	unsigned long temp_sys_call_table_addr;
	temp_sys_call_table_addr = kallsyms_lookup_name("sys_call_table"); 

	if (sys_call_table_addr == 0) { 
		return -1;
	} 
	
	printk("Found sys_call_table: %lx\n", (unsigned long)temp_sys_call_table_addr); 
	*sys_call_table_addr = (void *)temp_sys_call_table_addr; 

	return 0; 
} 

static int init_hook_init(struct hook_ctx *ctx)
{
	if (ctx == NULL) {
		return -1;
	}

	if (obtain_sys_call_table_addr((void **)&ctx->sys_call_table_addr) != 0) {
		return -1;
	}

	memset(srctable(ctx),0,tablesize);
	memset(objtable(ctx),0,tablesize);

	return 0;
}

static int install_hook(struct hook_ctx *ctx,unsigned int syscallnum,void *function)
{
	if (ctx == NULL) {
		return -1;
	}

	srctable(ctx)[syscallnum] = systable(ctx)[syscallnum];
	objtable(ctx)[syscallnum] = function;

	disable_write_protect();
	systable(ctx)[syscallnum] = function;
	enable_write_protect();

	printk("hook sysnum = %d\n",syscallnum);

	return 0;
}

static int uninstall_hook(struct hook_ctx *ctx,unsigned int syscallnum)
{
	if (ctx == NULL) {
		return -1;
	}

	if (srctable(ctx)[syscallnum] == 0) {
		return 0;
	}

	disable_write_protect();
	systable(ctx)[syscallnum] = srctable(ctx)[syscallnum];
	enable_write_protect();

	srctable(ctx)[syscallnum] = 0;
	objtable(ctx)[syscallnum] = 0;
	printk("uninstall_hook syscallnum = %d\n",syscallnum);

	return 0;
}

static int uninit_hook_init(struct hook_ctx *ctx)
{
	int i = 0;
	if (ctx == NULL) {
		return -1;
	}

	for (i = 0;i < NR_syscalls;i++) {
		uninstall_hook(ctx,i);
	}

	return 0;
}

static int do_login(struct message_login *login)
{
	if (!login) {
		return -1;
	}

	if(hook_dev->islogin) {
		return 0;
	}
	
	if (!strcmp(login->user,HOOK_USER) && !strcmp(login->passwd,HOOK_PASSWD)) {
		hook_dev->islogin = 1;
		printk("login succeed\n");
	}

	return 0;
}

static int do_hook(struct message_hook *hk)
{
	int ret = 0;
	int i = 0;
	
	if (!hook_dev->islogin || !hk) {
		return -1;
	}

	if (hk->sysnum < 0 || hk->sysnum >= NR_syscalls) {
		return -1;
	}

	for (i = 0;hook_modules[i];i++) {
		//printk("--%d * %d--\n",hk->sysnum,hook_modules[i]->syscallnum);
		if (hk->sysnum == hook_modules[i]->syscallnum) {
			if (hk->ishook) {
				ret = install_hook(&hook_dev->hctx,hk->sysnum,hook_modules[i]->hook_function);
				printk("hook start num = %d %s->%s\n",hk->sysnum,__FILE__,__FUNCTION__);
			} else {
				ret = uninstall_hook(&hook_dev->hctx,hk->sysnum);
				printk("unhook start num = %d %s->%s\n",hk->sysnum,__FILE__,__FUNCTION__);
			}
			break;
		}
	}

	if (!hook_modules[i]) {
		printk("no hook function %s->%s\n",__FILE__,__FUNCTION__);
	}
	
	if (!ret) {
		printk("hook succeed %s->%s\n",__FILE__,__FUNCTION__);
		return -1;
	}

	return 0;
}

static int do_path(struct message_path *path)
{
	struct listen_path *lpa = NULL;
	ngx_queue_t *q = NULL;
	
	if (!path) {
		return -1;
	}

	if (path->isenter) {
		lpa = kmalloc(sizeof(struct listen_path), GFP_KERNEL);
		if (lpa == NULL) {
			printk("do_path kmalloc error\n");
			return -1;
		}
		
		if (path->iskeyword) {
			hook_dev->iskeymod = 1;
			memcpy(lpa->path,path->path,PATHMAX);
			printk("keyword %s %s\n",lpa->path,path->path);
			ngx_queue_insert_head(&hook_dev->keywords, &lpa->queue_node);
			printk("add keyword end\n");
 		} else {
			memcpy(lpa->path,path->path,PATHMAX);
			printk("%s %s\n",lpa->path,path->path);
			ngx_queue_insert_head(&hook_dev->paths, &lpa->queue_node);	 
		}

	} else {
		if (path->iskeyword) {
			q = &hook_dev->paths;
			for (q = ngx_queue_next(q);q != ngx_queue_sentinel(&hook_dev->paths);q = ngx_queue_next(q)) {
				lpa = ngx_queue_data(q, struct listen_path, queue_node);
				if(strcmp(path->path,lpa->path) == 0) {
					break;
				}
			} 
			
			if (q == ngx_queue_sentinel(&hook_dev->paths)) {
				printk("no path\n");
				return 0;
			}

			printk("delete path : %s\n",lpa->path);
			ngx_queue_remove(&lpa->queue_node);
		} else {
			q = &hook_dev->keywords;
			for (q = ngx_queue_next(q);q != ngx_queue_sentinel(&hook_dev->keywords);q = ngx_queue_next(q)) {
				lpa = ngx_queue_data(q, struct listen_path, queue_node);
				if(strcmp(path->path,lpa->path) == 0) {
					break;
				}
			} 
			
			if (q == ngx_queue_sentinel(&hook_dev->keywords)) {
				printk("no keyword\n");
				return 0;
			}
			printk("delete keyword : %s\n",lpa->path);
			ngx_queue_remove(&lpa->queue_node);
		}
		
		kfree(lpa);
	}

	return 0;
}

static int do_domain(struct message_domain *domain){
	struct listen_addr *la = NULL;
	ngx_queue_t *q = NULL;

	if (!domain) {
		return -1;
	}

	if (domain->enter) {
		la = kmalloc(sizeof(struct listen_addr), GFP_KERNEL);
		if (la == NULL) {
			printk("kmalloc error\n");
			return -1;
		}

		if (domain->rewrite) {
			memcpy(la->srcip,domain->srcip,IPLEN);
			memcpy(la->objip,domain->objip,IPLEN);
			//printk("%s ->>  %s\n",la->srcip,la->objip);
			ngx_queue_insert_head(&hook_dev->addrs, &la->queue_node);
		} else if (domain->ban) {
			memcpy(la->srcip,domain->srcip,IPLEN);
			//printk("ban ip %s\n",la->srcip);
			ngx_queue_insert_head(&hook_dev->bans, &la->queue_node);
		}
		
	} else {
		if (domain->rewrite) {
			q = &hook_dev->addrs;
			for (q = ngx_queue_next(q);q != ngx_queue_sentinel(&hook_dev->addrs);q = ngx_queue_next(q)) {
				la = ngx_queue_data(q, struct listen_addr, queue_node);
				if(strcmp(domain->srcip,la->srcip) == 0) {
					break;
				}
			} 
			
			if (q == ngx_queue_sentinel(&hook_dev->addrs)) {
				printk("no rewrite\n");
				return 0;
			}

			printk("delete srcip : %s\n",la->srcip);
			ngx_queue_remove(&la->queue_node);
			kfree(la);
		} else if (domain->ban) {
			q = &hook_dev->bans;
			for (q = ngx_queue_next(q);q != ngx_queue_sentinel(&hook_dev->bans);q = ngx_queue_next(q)) {
				la = ngx_queue_data(q, struct listen_addr, queue_node);
				if(strcmp(domain->srcip,la->srcip) == 0) {
					break;
				}
			} 
			
			if (q == ngx_queue_sentinel(&hook_dev->bans)) {
				printk("no bans\n");
				return 0;
			}

			printk("delete ban ip : %s\n",la->srcip);
			ngx_queue_remove(&la->queue_node);
			kfree(la);
		}
	}
	return 0;
}

static int message_parse(struct messagepro *pro)
{
	if(!pro){
		return -1;
	}

	if (islogin(pro)) {
		do_login(prologin(pro));
	} else if(ishook(pro)) {
		do_hook(prohook(pro));
	} else if(ispath(pro)) {
		do_path(propath(pro));
	} else if(isdomain(pro)) {
		do_domain(prodomain(pro));
	}

	return 0;
}

static int hooked_open(struct inode *inode, struct file *filp)
{
	init_hook_init(&hook_dev->hctx);

	return 0;
}

static ssize_t hooked_read(struct file *filp, char __user *buffer, size_t size, loff_t *ppos)
{
	int ret = 0;
	ngx_queue_t *q = NULL;
	struct log_data *plog = NULL;

	if (ngx_queue_empty(&hook_dev->logs)) {
		if (filp->f_flags & O_NONBLOCK) return -EAGAIN;
		
		wait_event_interruptible(hook_dev->inq, !ngx_queue_empty(&hook_dev->logs));
	}

	if(ngx_queue_empty(&hook_dev->logs)){
		return  -ERESTARTSYS;
	}

	spin_lock(&hook_dev->hook_lock);
	q = ngx_queue_last(&hook_dev->logs);
	spin_unlock(&hook_dev->hook_lock);
	plog = ngx_queue_data(q, struct log_data, queue_node);
	
	if (copy_to_user(buffer, plog->addr, LOGMAX)) {
		ret = -EFAULT;
	} else {
		ret = PATHMAX;
		spin_lock(&hook_dev->hook_lock);
		ngx_queue_remove(q);
		spin_unlock(&hook_dev->hook_lock);
		kfree(plog);
	}

	return ret;
}

static ssize_t hooked_write(struct file *filp, const char __user *buffer, size_t size, loff_t *ppos)
{
	char userdata[MESSLEN] = {0};
	struct messagepro *pro = (struct messagepro *)userdata;
	
	int count = size;
	
	if (copy_from_user(userdata, buffer, size)) {
		return -EFAULT;
	}

	if (message_parse(pro) < 0) {
		return -EFAULT;
	}

	return count;
}

static unsigned int hooked_poll(struct file *filp, struct poll_table_struct *wait)
{
	unsigned int mask = 0;

	poll_wait(filp, &hook_dev->inq, wait);

	if (!ngx_queue_empty(&hook_dev->logs)) {
		mask |= (POLLIN | POLLRDNORM);
	}
	
	return mask;
}

static int clean_paths(ngx_queue_t *q)
{
	struct listen_path *la = ngx_queue_data(q,struct listen_path,queue_node);
	if (la == NULL) {
		printk("data = null %s -> %s",__FILE__,__FUNCTION__);
		return -1;
	}

	printk("remove %s\n",la->path);
	kfree(la);

	return 0;
}

static int clean_addrs(ngx_queue_t *q)
{
	struct listen_addr *la = ngx_queue_data(q,struct listen_addr,queue_node);
	if (la == NULL) {
		printk("data = null %s -> %s",__FILE__,__FUNCTION__);
		return -1;
	}

	printk("remove %s\n",la->srcip);
	kfree(la);

	return 0;
}

static int clean_logs(ngx_queue_t *q)
{
	struct log_data *la = ngx_queue_data(q,struct log_data,queue_node);
	if (la == NULL) {
		printk("data = null %s -> %s",__FILE__,__FUNCTION__);
		return -1;
	}

	printk("remove rewrite %s\n",la->addr);
	kfree(la);

	return 0;
}

static int clean_bans(ngx_queue_t *q)
{
	struct listen_addr *la = ngx_queue_data(q,struct listen_addr,queue_node);
	if (la == NULL) {
		printk("data = null %s -> %s",__FILE__,__FUNCTION__);
		return -1;
	}

	printk("remove ban ip %s\n",la->srcip);
	kfree(la);

	return 0;
}

static int clean_keywords(ngx_queue_t *q)
{
	struct listen_path *la = ngx_queue_data(q,struct listen_path,queue_node);
	if (la == NULL) {
		printk("keyword = null %s -> %s",__FILE__,__FUNCTION__);
		return -1;
	}

	printk("remove keyword %s\n",la->path);
	kfree(la);

	return 0;
}

static int hooked_close(struct inode *inode, struct file *filp)
{
	uninit_hook_init(&hook_dev->hctx);
	queue_clean(&hook_dev->paths,clean_paths);
	queue_clean(&hook_dev->addrs,clean_addrs);
	queue_clean(&hook_dev->logs ,clean_logs);
	queue_clean(&hook_dev->keywords ,clean_keywords);
	queue_clean(&hook_dev->bans ,clean_bans);

	return 0;
}

static struct file_operations hook_fops = {
	.open = hooked_open,
	.read = hooked_read,
	.write = hooked_write,
	.release = hooked_close,
	.poll = hooked_poll,
};

static int hooked_init(void) {
	int ret = 0;
	printk("+ Loading hook_mkdir module\n"); 
	
	hook_dev = kmalloc(sizeof(struct hook_data), GFP_KERNEL);
	memset(hook_dev ,0,sizeof(struct hook_data));
	if (hook_dev == NULL) {
		printk("kalloc error\n");
		ret = -ENOMEM;
		goto err_ret;
	}
	//1 申请一个设备号
	hook_dev->major = MAJOR_NUM;
	ret = register_chrdev(hook_dev->major, "hook_dev", &hook_fops);
	if (ret < 0) {
		printk("register_chrdev error\n");
		ret = -EINVAL;
		goto err_free;
	}
	//2 创建一个设备文件
	hook_dev->cls = class_create(THIS_MODULE, "hook_cls");
	if (hook_dev->cls == NULL) {
		printk("class_create error\n");
		ret = -EINVAL;
		goto err_unregister;
	}
	// 在/dev/下面有一个"hook"
	hook_dev->dev = device_create(hook_dev->cls, NULL ,MKDEV(hook_dev->major,0), NULL, "hook");
	if (hook_dev->dev == NULL) {
		printk("device_create error\n");
		ret = -EINVAL;
		goto err_class_destroy;
	}

	//初始化队列
	init_waitqueue_head(&hook_dev->inq);
	ngx_queue_init(&hook_dev->paths);
	ngx_queue_init(&hook_dev->addrs);
	ngx_queue_init(&hook_dev->logs);
	ngx_queue_init(&hook_dev->keywords);
	ngx_queue_init(&hook_dev->bans);
	//初始化锁
	spin_lock_init(&hook_dev->hook_lock);

	return 0;

err_class_destroy:
	class_destroy(hook_dev->cls);

err_unregister:
	unregister_chrdev(hook_dev->major,"hook_dev");
	
err_free:
	kfree(hook_dev);

err_ret:
	return ret;
}

static void hooked_exit(void) { 
	printk("+ Unloading hook_execve module\n");

	device_destroy(hook_dev->cls, MKDEV(hook_dev->major,0));
	
	class_destroy(hook_dev->cls);

	unregister_chrdev(hook_dev->major,"hook_dev");
	
	kfree(hook_dev);
}

module_init(hooked_init); 
module_exit(hooked_exit);