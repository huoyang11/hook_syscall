#include "module.h"
#include "messagepro.h"
#include "ngx_queue.h"
#include "hook_connect.h"
#include "drivelog.h"

#define REWRITE		5

static int check_rewrite(char *ip,struct listen_addr **pl)
{
	ngx_queue_t *q = NULL;
	struct listen_addr *lpa = NULL;

	if (!ip) {
		return -1;
	}

	q = &hook_dev->addrs;
	for (q = ngx_queue_next(q);q != ngx_queue_sentinel(&hook_dev->addrs);q = ngx_queue_next(q)) {
		lpa = ngx_queue_data(q, struct listen_addr, queue_node);
		if(strncmp(ip,lpa->srcip,IPLEN) == 0) {
			*pl = lpa;
			return -REWRITE;
		}
	}

	return 0;
}

static char *addr_ntoa(struct in_addr ina)
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

static int inet_pton(const char *src, const char *end, unsigned char *dst)
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
    memcpy(dst, tmp, 4);
    return 1;
}

static int hook_connect(int fd, struct sockaddr __user *uservaddr, int addrlen)
{
	int check = 0;
	char *str_ptr = NULL;
	unsigned int port = 0;
	unsigned int family = 0;
	unsigned int iaddr = 0;
	struct listen_addr *lpa = NULL;
	struct log_data *plog = kmalloc(sizeof(struct log_data),GFP_KERNEL);
	struct sockaddr_in *sr = (struct sockaddr_in *)uservaddr;
	struct sockaddr_in *saddr = kmalloc(sizeof(struct sockaddr_in),GFP_KERNEL);

	str_ptr = addr_ntoa(((struct sockaddr_in *)uservaddr)->sin_addr);	
	port = ntohs(sr->sin_port);
	family = sr->sin_family;

	//log
	if (plog) {
		get_log_time(plog->addr);
		get_task_path(plog->addr);
		sprintf(plog->addr,"%s ip:%s family %u port:%u",plog->addr,str_ptr,family,port);

		spin_lock(&hook_dev->hook_lock);
		ngx_queue_insert_head(&hook_dev->logs,&plog->queue_node);
		spin_unlock(&hook_dev->hook_lock);
		wake_up_interruptible(&hook_dev->inq);
	}

	check = check_rewrite(str_ptr,&lpa);

	if (check == -REWRITE) {
		inet_pton(lpa->objip,lpa->objip + strlen(lpa->objip),(char *)&iaddr);
		if (saddr == NULL) {
			printk("kmalloc error\n");
			goto end;
		}

		memcpy(saddr,uservaddr,addrlen);
		saddr->sin_addr = *((struct in_addr*)&iaddr);
		
		if (copy_to_user(uservaddr,saddr,addrlen)) {
			printk("connect copy error %s -> %s\n",__FILE__,__FUNCTION__);
			goto end;
		}
	}

end:
	return srctbcall(&hook_dev->hctx,type_connect,__NR_connect)(fd,uservaddr,addrlen);
}


hook_module_t hook_connect_module = {
	NULL,
	NULL,
	NULL,
	NULL,
	__NR_connect,
	hook_connect
};
