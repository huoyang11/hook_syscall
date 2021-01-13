#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/poll.h>
#include <linux/unistd.h>


#include "messagepro.h"

#define HOOK_USER		"yh"
#define HOOK_PASSWD		"123456"

#define LOOPNUM			10000

#define DISOPEN			"/home/yh/hook/hook.c"
#define DISOPENDIR		"/home/yh/Public"

#define BAIDU			"14.215.177.38"
#define XINLANG			"183.60.208.224"

int main(int argc,char *argv[])
{
	int ret = 0;
	int i = 0;
	struct messagepro pro[1] = {0};
	int fd = open("/dev/hook",O_RDWR);
	if(fd == -1){
		perror("open dev error");
		return -1;
	}

	pro->type = PROLOGIN;
	strncpy(prologin(pro)->user,HOOK_USER,strlen(HOOK_USER));
	strncpy(prologin(pro)->passwd,HOOK_PASSWD,strlen(HOOK_PASSWD));
	
	ret = write(fd,pro,MESSLEN);
	if(ret < 0){
		printf("login error\n");
		return -1;
	}

	memset(pro,0,MESSLEN);
	pro->type = PROHOOK;
	prohook(pro)->sysnum = __NR_open;
	prohook(pro)->ishook = 1;
	ret = write(fd,pro,MESSLEN);
	if(ret < 0){
		printf("hook function error\n");
		return -1;
	}

	memset(pro,0,MESSLEN);
	pro->type = PROHOOK;
	prohook(pro)->sysnum = __NR_connect;
	prohook(pro)->ishook = 1;
	ret = write(fd,pro,MESSLEN);
	if(ret < 0){
		printf("hook function error\n");
		return -1;
	}

	memset(pro,0,MESSLEN);
	pro->type = PROPATH;
	propath(pro)->isenter = 1;
	memcpy(propath(pro)->path,DISOPEN,strlen(DISOPEN));
	ret = write(fd,pro,MESSLEN);
	if(ret < 0){
		printf("hook function error\n");
		return -1;
	}

	memset(pro,0,MESSLEN);
	pro->type = PROPATH;
	propath(pro)->isenter = 1;
	memcpy(propath(pro)->path,DISOPENDIR,strlen(DISOPENDIR));
	ret = write(fd,pro,MESSLEN);
	if(ret < 0){
		printf("hook function error\n");
		return -1;
	}

	memset(pro,0,MESSLEN);
	pro->type = PROREWRITE;
	prorewrite(pro)->enter = 1;
	memcpy(prorewrite(pro)->srcip,BAIDU,IPLEN);
	memcpy(prorewrite(pro)->objip,XINLANG,IPLEN);
	ret = write(fd,pro,MESSLEN);
	if(ret < 0){
		printf("hook function error\n");
		return -1;
	}

	char buf[1024] = {0};
	int n = 0;
	
	for (i = 0;i < LOOPNUM;i++) {
		n = read(fd,buf,1024);
		printf(">%s\n",buf);
		if(n < 0) {
			perror("read");
			break;
		}
	}

	close(fd);

	return 0;
}
