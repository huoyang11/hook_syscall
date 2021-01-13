#include "hook_open.h"
#include "module.h"
#include "messagepro.h"

typedef int (*type_close)(unsigned int);

#define NOOPEN  5

static int get_log_time(char *str)
{
	struct timex  txc;
	struct rtc_time tm;

	if(str == NULL){
		return -1;
	}

	do_gettimeofday(&(txc.time));//当前时间
	rtc_time_to_tm(txc.time.tv_sec,&tm);

	sprintf(str,"UTC time :%d-%02d-%02d %02d:%02d:%02d",tm.tm_year+1900,tm.tm_mon, tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec);

	return 0;
}

static int get_task_path(char *str)
{
	char *ptr;
	int err;
	char link[100], buf[256];
	struct path path;

	if (str == NULL) {
		return -1;
	}

	sprintf(link, "/proc/%d/exe", current->pid);
 
	err = kern_path(link, LOOKUP_FOLLOW, &path);
	if ( !err )    
	{   
    	ptr = d_path(&path, buf, 256);      
    	if (IS_ERR(ptr)) {
			printk("task path error\n");
	    	return -1;
		}
		sprintf(str,"%s process:%s -> pid:%d ",str,ptr,current->pid);
    	path_put(&path);
	}

	return 0;
}

static int open_user_file(const char *filename, int flags, unsigned short mode)
{
	long fp = 0;
	fp = ((type_open)(srctable(&hook_dev->hctx)[__NR_open]))(filename,flags,mode);

	return fp;
}

static int check_open(char *file_path)
{
	int ret = 0;
	ngx_queue_t *q = NULL;
	struct listen_path *lpa = NULL;
	
	if( file_path == NULL) {
		return -1;
	}

	q = &hook_dev->paths;
	for (q = ngx_queue_next(q);q != ngx_queue_sentinel(&hook_dev->paths);q = ngx_queue_next(q)) {
		lpa = ngx_queue_data(q, struct listen_path, queue_node);
		if(strstr(file_path,lpa->path) == file_path) {
			return -NOOPEN;
		}
	} 

	return ret;
}

static int get_file_cwd(char *str,int fd,const char *filename,int *check)
{
	struct file *fe = NULL;
	char  path[PATHMAX] = {0};
	char *ppath = path;

	if (str == NULL) {
		return -1;
	}

	if (fd < 0) {
		if (fd == -ENOENT) {
			sprintf(str,"%s filepath : %s",str,filename);		
    	}
	    goto end;
    }

	fe = current->files->fdt->fd[fd];
	ppath = d_path(&fe->f_path, ppath, 128);
	sprintf(str,"%s filepath : %s",str,ppath);
	*check = check_open(ppath);
	//path_put(&fe->f_path);

end:
	return fd;
}

static asmlinkage long hook_open(const char __user * filename, int flags, unsigned short mode)
{
	int filename_size= 4096;
	char *file_str = NULL;
	struct listen_path *ppath = NULL;
	int fd = 0;
	int check = 0;

	file_str = kmalloc(filename_size, GFP_KERNEL);
	ppath = kmalloc(sizeof(struct listen_path), GFP_KERNEL);
	if (!file_str && !ppath) {
		printk("file:%s -> %s kmalloc error\n",__FILE__,__FUNCTION__);
		goto end;
	}

	memset(file_str, 0, filename_size );
	memset(ppath,0,sizeof(struct listen_path));

	//组时间
	get_log_time(file_str);
	//组进程路径
	get_task_path(file_str);
	
	fd = open_user_file(filename,flags,mode);
	get_file_cwd(file_str,fd,filename,&check);
	

	memcpy(ppath->path,file_str,PATHMAX);
	spin_lock(&hook_dev->hook_lock);
	ngx_queue_insert_head(&hook_dev->logs,&ppath->queue_node);
	spin_unlock(&hook_dev->hook_lock);

	wake_up_interruptible(&hook_dev->inq);

	if (check == -NOOPEN) {
		if(fd >= 0) {
			if (srctable(&hook_dev->hctx) == 0) {
				printk("sys %lx\n",(unsigned long)(systable(&hook_dev->hctx)[__NR_close]));
				((type_close)(systable(&hook_dev->hctx)[__NR_close]))(fd);
			} else {
				printk("src %lx\n",(unsigned long)(srctable(&hook_dev->hctx)[__NR_close]));
				((type_close)(srctable(&hook_dev->hctx)[__NR_close]))(fd);
			}
		}
	
		return -1;
	}
end:

	if (file_str != NULL) {   
		kfree(file_str);
	}
	
#if 1
	if (fd < 0) {
		return ((type_open)(srctable(&hook_dev->hctx)[__NR_open]))(filename,flags,mode);
	} else {
		return fd;
	}
#endif
	//return ((type_open)(srctable(&hook_dev->hctx)[__NR_open]))(filename,flags,mode);
}

hook_module_t hook_open_module = {
	NULL,
	NULL,
	NULL,
	NULL,
	__NR_open,
	hook_open
};

