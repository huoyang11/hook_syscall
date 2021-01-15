#include "module.h"
#include "messagepro.h"
#include "ngx_queue.h"
#include "hook_connect.h"

char *addr_ntoa(struct in_addr ina)
{
	static char buf[IPLEN];
	unsigned char *ucp = (unsigned char *)&ina;

	sprintf(buf, "%d.%d.%d.%d",
			ucp[0] & 0xff,
			ucp[1] & 0xff,
			ucp[2] & 0xff,
			ucp[3] & 0xff);
	return buf;	
}

int inet_pton(const char *src, const char *end, unsigned char *dst)
{
    int saw_digit, octets, ch;
    unsigned char tmp[4], *tp;

    saw_digit = 0;
    octets = 0;
    *(tp = tmp) = 0;
    while (src < end) {
        ch = *src++;
        if (ch >= '0' && ch <= '9') {
          unsigned int new = *tp * 10 + (ch - '0');

          if (saw_digit && *tp == 0)
            return 0;
          if (new > 255)
            return 0;
          *tp = new;
          if (! saw_digit) {
                if (++octets > 4)
                    return 0;
                saw_digit = 1;
            }
        } else if (ch == '.' && saw_digit) {
        if (octets == 4)
            return 0;
          *++tp = 0;
          saw_digit = 0;
        } else
            return 0;
    }
    if (octets < 4)
        return 0;
    memcpy (dst, tmp, 4);
    return 1;
}

static int get_task_path(void)
{
	char *ptr;
	int err;
	char link[100], buf[256];
	struct path path;

	sprintf(link, "/proc/%d/exe", current->pid);
 
	err = kern_path(link, LOOKUP_FOLLOW, &path);
	if ( !err )    
	{   
    	ptr = d_path(&path, buf, 256);      
    	if (IS_ERR(ptr)) {
			printk("task path error\n");
	    	return -1;
		}
		printk("process:%s -> pid:%d ",ptr,current->pid);
    	path_put(&path);
	}

	return 0;
}


int hook_connect(int fd, struct sockaddr __user *uservaddr, int addrlen)
{
	ngx_queue_t *q = NULL;
	unsigned int port = 0;
	unsigned int family = 0;
	unsigned int iaddr = 0;
	struct listen_addr *lpa = NULL;
	char* str_ptr = NULL;
	struct sockaddr_in *sr = (struct sockaddr_in *)uservaddr;
	struct sockaddr_in *saddr = kmalloc(sizeof(struct sockaddr_in),GFP_KERNEL);

	str_ptr = addr_ntoa(((struct sockaddr_in *)uservaddr)->sin_addr);	
	port = ntohs(sr->sin_port);
	family = sr->sin_family;
	
	q = &hook_dev->addrs;
	for (q = ngx_queue_next(q);q != ngx_queue_sentinel(&hook_dev->addrs);q = ngx_queue_next(q)) {
		lpa = ngx_queue_data(q, struct listen_addr, queue_node);
		if(strncmp(str_ptr,lpa->srcip,IPLEN) == 0) {
			//printk("src:%s to obj:%s\n",lpa->srcip,lpa->objip);
			inet_pton(lpa->objip,lpa->objip + strlen(lpa->objip),(char *)&iaddr);
			if (saddr == NULL) {
				printk("kmalloc error\n");
				goto end;
			}

			memcpy(saddr,uservaddr,addrlen);
			saddr->sin_addr = *((struct in_addr*)&iaddr);

			get_task_path();
			printk("src:%s family %u port:%u\n",str_ptr,family,port);
			
			if (copy_to_user(uservaddr,saddr,addrlen)) {
				printk("connect copy error\n");
				goto end;
			}

			str_ptr = addr_ntoa(((struct sockaddr_in *)uservaddr)->sin_addr);	
			printk("too:%s family %u port:%u\n",str_ptr,family,port);
			kfree(saddr);
			//str_ptr = addr_ntoa(((struct sockaddr_in *)uservaddr)->sin_addr);
			//printk("obj:%s port:%d\n",str_ptr,((struct sockaddr_in *)uservaddr)->sin_port);
		}

		if(port == 443) {
			printk("-----src:%s family %u port:%u----------\n",str_ptr,family,port);
		}
	} 

	//printk("%s",str_ptr);
end:
	return srctbcall(&hook_dev->hctx,type_connect,__NR_connect)(fd,uservaddr,addrlen);
	//return ((type_connect)(srctable(&hook_dev->hctx)[__NR_connect]))(fd,uservaddr,addrlen);
}


hook_module_t hook_connect_module = {
	NULL,
	NULL,
	NULL,
	NULL,
	__NR_connect,
	hook_connect
};
