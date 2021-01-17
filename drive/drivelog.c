#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/rtc.h>

int get_log_time(char *str)
{
	struct timex  txc;
	struct rtc_time tm;

	if(str == NULL){
		return -1;
	}

	do_gettimeofday(&(txc.time));//当前时间
	rtc_time_to_tm(txc.time.tv_sec,&tm);

	sprintf(str,"UTC time :%d-%02d-%02d %02d:%02d:%02d",tm.tm_year+1900,tm.tm_mon + 1, tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec);

	return 0;
}

int get_task_path(char *str)
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