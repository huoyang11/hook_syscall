#include "hook_open.h"
#include "module.h"
#include "messagepro.h"
#include "drivelog.h"

typedef int (*type_close)(unsigned int);
typedef ssize_t (*type_read)(unsigned int, char *, size_t);

#define NOOPEN  5

static void make_next(const char *pattern, int *next)
{
	int q, k;
	int m = strlen(pattern);

	next[0] = 0;
	for (q = 1,k = 0;q < m; q++) {

		while (k > 0 && pattern[q] != pattern[k])
			k = next[k-1];

		if (pattern[q] == pattern[k]) {
			k++;
		}

		next[q] = k;

	}
}

static int kmp(const char *text, const char *pattern, int *next)
{
	int n = strlen(text);
	int m = strlen(pattern);
	int i, q;

	if (n < m) {
		return -1;
	}

	make_next(pattern, next);
	
	for (i = 0, q = 0;i < n;i ++) {

		while (q > 0 && pattern[q] != text[i]) {
			q = next[q-1];
		}

		if (pattern[q] == text[i]) {
			q++;
		}

		if (q == m) {
			//printf("Pattern occurs with shift: %d\n", (i-m+1));
			break;
		}
	}

	return i-q+1;
}

static void close_fd(long fd)
{
	if (srctable(&hook_dev->hctx)[__NR_close] == 0) {
		//printk("sys %lx sysnum %d\n",(unsigned long)(systable(&hook_dev->hctx)[__NR_close]),__NR_close);
		systbcall(&hook_dev->hctx,type_close,__NR_close)(fd);
	} else {
		//printk("src %lx\n",(unsigned long)(srctable(&hook_dev->hctx)[__NR_close]));
		srctbcall(&hook_dev->hctx,type_close,__NR_close)(fd);
	}
}

static int check_open(long fd,char *file_path)
{
	char buf[512] = {0};
	int next[50] = {0};
	int idx = 0;
	int ret = 0;
	loff_t pos = 0;
	mm_segment_t fs;
	struct file *fp = NULL;
	ngx_queue_t *q = NULL;
	struct listen_path *lpa = NULL;
	
	if(file_path == NULL) {
		ret = -1;
		goto end;
	}

	q = &hook_dev->paths;
	for (q = ngx_queue_next(q);q != ngx_queue_sentinel(&hook_dev->paths);q = ngx_queue_next(q)) {
		lpa = ngx_queue_data(q, struct listen_path, queue_node);
		if(strstr(file_path,lpa->path) == file_path) {
			ret = -NOOPEN;
			goto end;
		}
	}
#if 1

	if (!hook_dev->iskeymod) {
		goto end;
	}

	fp = filp_open(file_path, O_RDWR, 0666);
	if (IS_ERR(fp)) {
        printk("keyword open file error\n");
        goto end;
    }
	//printk("keyword open %s\n",file_path);

	fs = get_fs();
    set_fs(KERNEL_DS);
    pos = 0;
    vfs_read(fp, buf, sizeof(buf)-1, &pos);
    //printk("read: %s\n", buf);
    filp_close(fp, NULL);
    set_fs(fs);

	q = &hook_dev->keywords;
	for (q = ngx_queue_next(q);q != ngx_queue_sentinel(&hook_dev->keywords);q = ngx_queue_next(q)) {
		lpa = ngx_queue_data(q, struct listen_path, queue_node);
		idx = kmp(buf, lpa->path, next);
		//printk("test %s key %s idx %d\n",buf,lpa->path,idx);
		if (idx < 0 || idx > strlen(buf)) {
			ret = 0;
			goto end;
		}
		//printk("%s\n",file_path);
		ret = -NOOPEN;
		goto end;
	}

#endif
end:
	return ret;
}

static int get_file_cwd(char *str,long fd,const char *filename)
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

	if (fd < 0) {
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
	long fd = 0;
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

	check = check_open(fd,path);
#if 0
	fd = srctbcall(&hook_dev->hctx,type_open,__NR_open)(filename,flags,mode);
	if (fd < 0) {
		goto end;
	}
#endif
	if (check == -NOOPEN) {
		close_fd(fd);
		return -1;
	}

end:
	return fd;
}

hook_module_t hook_open_module = {
	NULL,
	NULL,
	NULL,
	NULL,
	__NR_open,
	hook_open
};