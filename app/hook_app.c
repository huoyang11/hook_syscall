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

#define LOOPNUM			2000

#define BAIDU			"14.215.177.38"
#define XINLANG			"183.60.208.224"

#define KEYWORD			"1111122223"

int main(int argc,char *argv[])
{
	int i = 0;
	
	int fd = open("/dev/hook",O_RDWR);
	if(fd == -1){
		perror("open dev error");
		return -1;
	}

	if (login(fd,HOOK_USER,HOOK_PASSWD) != 0) {
		printf("login error\n");
		return -1;
	}

	if (load_config(fd,"./config.lua") != 0) {
		printf("load config error\n");
		return -1;
	}
#if 0
	if (addkeyword(fd,KEYWORD,1)) {
		printf("addkeyword error\n");
		return -1;
	}
#endif
	char buf[1024] = {0};
	int n = 0;
	
	for (;;) {
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
