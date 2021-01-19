#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/poll.h>
#include <linux/unistd.h>

#include "messagepro.h"
#include "request.h"
#include "exluaconf.h"

#define HOOK_USER		"yh"
#define HOOK_PASSWD		"123456"

int fd = 0;

int drive_run(const char *config)
{
	if (!config) {
		return -1;
	}

	fd = open("/dev/hook",O_RDWR);
	if(fd == -1){
		perror("open dev error");
		return -1;
	}

	if (login(fd,HOOK_USER,HOOK_PASSWD) != 0) {
		printf("login error\n");
		return -1;
	}

	if (load_config(fd,config) != 0) {
		printf("load config error\n");
		return -1;
	}

	return 0;
}

int rerun()
{
	close(fd);
	drive_run("./config.lua");
}

int main(int argc,char *argv[])
{
	int i = 0;
	char buf[1024] = {0};
	int n = 0;
	
	drive_run("./config.lua");

	for (;;) {
		n = read(fd,buf,sizeof(buf) - 1);
		printf(">%s\n",buf);
		memset(buf,0,sizeof(buf));
	}

	close(fd);

	return 0;
}
