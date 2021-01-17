#include "hook_open.h"
#include "module.h"
#include "messagepro.h"
#include "drivelog.h"

typedef int (*type_close)(unsigned int);

#define NOOPEN  5

void make_next(const char *pattern, int *next) {

	int q, k;
	int m = strlen(pattern);

	next[0] = 0;
	for (q = 1,k = 0;q < m; q ++) {

		while (k > 0 && pattern[q] != pattern[k])
			k = next[k-1];

		if (pattern[q] == pattern[k]) {
			k ++;
		}

		next[q] = k;

	}
}

int kmp(const char *text, const char *pattern, int *next) {

	int n = strlen(text);
	int m = strlen(pattern);
	int i, q;

	make_next(pattern, next);
	
	for (i = 0, q = 0;i < n;i ++) {

		while (q > 0 && pattern[q] != text[i]) {
			q = next[q-1];
		}

		if (pattern[q] == text[i]) {
			q ++;
		}

		if (q == m) {
			//printf("Pattern occurs with shift: %d\n", (i-m+1));
			break;
		}
	}

	return i-q+1;
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

static int get_file_cwd(char *str,int fd,const char *filename)
{
	struct file *fe = NULL;
	char  path[PATHMAX] = {0};
	char *ppath = path;

	if (str == NULL) {
		return -1;
	}

	fe = current->files->fdt->fd[fd];
	if (fd == -ENOENT || !fe) {
		sprintf(str,"%s",filename);
		goto end;
	}

	ppath = d_path(&fe->f_path, ppath, PATHMAX);
	sprintf(str,"%s",ppath);
	//path_put(&fe->f_path);

end:
	return fd;
}

static asmlinkage long hook_open(const char __user * filename, int flags, unsigned short mode)
{
	int fd = 0;
	int check = 0;
	char path[PATHMAX] = {0};
	struct log_data *plog = NULL;
	
	fd = srctbcall(&hook_dev->hctx,type_open,__NR_open)(filename,flags,mode);
	if (fd < 0) {
		goto end;
	}

	plog = kmalloc(sizeof(struct log_data), GFP_KERNEL);
	memset(plog,0,sizeof(struct log_data));

	get_file_cwd(path,fd,filename);

	if (plog) {
		get_log_time(plog->addr);
		get_task_path(plog->addr);
		sprintf(plog->addr,"%s filepath: %s",plog->addr,path);

		spin_lock(&hook_dev->hook_lock);
		ngx_queue_insert_head(&hook_dev->logs,&plog->queue_node);
		spin_unlock(&hook_dev->hook_lock);
		wake_up_interruptible(&hook_dev->inq);
	}	

	check = check_open(path);
	
	if (check == -NOOPEN) {
		if (srctable(&hook_dev->hctx)[__NR_close] == 0) {
			//printk("sys %lx sysnum %d\n",(unsigned long)(systable(&hook_dev->hctx)[__NR_close]),__NR_close);
			systbcall(&hook_dev->hctx,type_close,__NR_close)(fd);
		} else {
			//printk("src %lx\n",(unsigned long)(srctable(&hook_dev->hctx)[__NR_close]));
			srctbcall(&hook_dev->hctx,type_close,__NR_close)(fd);
		}
		return -1;
	}

end:
	return srctbcall(&hook_dev->hctx,type_open,__NR_open)(filename,flags,mode);
}

hook_module_t hook_open_module = {
	NULL,
	NULL,
	NULL,
	NULL,
	__NR_open,
	hook_open
};