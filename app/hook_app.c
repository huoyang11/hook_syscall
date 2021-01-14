#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/poll.h>
#include <linux/unistd.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "messagepro.h"

#define HOOK_USER		"yh"
#define HOOK_PASSWD		"123456"

#define LOOPNUM			2000

#define DISOPEN			"/home/yh/hook_syscall/hook.c"
#define DISOPENDIR		"/home/yh/Public"

#define BAIDU			"14.215.177.38"
#define XINLANG			"183.60.208.224"

int login(int fd,const char *user,const char *passwd)
{
	if (!user || !passwd || fd < 0) {
		return -1;
	}

	int ret = 0;
	struct messagepro pro[1] = {0};
	pro->type = PROLOGIN;
	strncpy(prologin(pro)->user,user,strlen(user));
	strncpy(prologin(pro)->passwd,passwd,strlen(passwd));

	ret = write(fd,pro,MESSLEN);
	if (ret < 0) {
		printf("login error\n");
		return -1;
	}

	return 0;
}

int hook_function(int fd,int sysnum)
{
	if (sysnum < 0 || fd < 0) {
		return -1;
	}

	int ret = 0;
	struct messagepro pro[1] = {0};
	pro->type = PROHOOK;
	prohook(pro)->sysnum = sysnum;
	prohook(pro)->ishook = 1;
	ret = write(fd,pro,MESSLEN);
	if(ret < 0){
		printf("hook function error\n");
		return -1;
	}

	return 0;
}

int dispath(int fd,const char *path)
{
	if (!path || fd < 0) {
		return -1;
	}

	int ret = 0;
	struct messagepro pro[1] = {0};
	pro->type = PROPATH;
	propath(pro)->isenter = 1;
	memcpy(propath(pro)->path,path,strlen(path));
	ret = write(fd,pro,MESSLEN);
	if(ret < 0){
		printf("hook function error\n");
		return -1;
	}

	return 0;
}

int hook_funs(int fd,...)
{
	int ret = 0;
	va_list v;
	va_start(v,fd);

	int num = va_arg(v,int);
	//printf("%d\n",num);
	while (num != -1) {
		ret = hook_function(fd,num);
		if(ret < 0) return -1;
		num = va_arg(v,int);
		//printf("%d\n",num);
	}

	va_end(v);

	return 0;
}

int dispaths(int fd,...)
{
	int ret = 0;
	va_list v;
	va_start(v,fd);

	char *path = va_arg(v,char *);
	//printf("%s\n",path);
	while (path != NULL) {
		ret = dispath(fd,path);
		if(ret < 0) return -1;
		path = va_arg(v,char *);
		if(path != NULL) printf("%s\n",path);
	}

	va_end(v);

	return 0;
}

int load_config_add_paths(int fd,const char *confpath)
{
	int i = 1;
	const char *str = NULL;
    //初始化lua环境
    lua_State *L = luaL_newstate();
    luaL_openlibs(L);
	//编译并执行
    int ret = luaL_loadfile(L,confpath) || lua_pcall(L,0,0,0);
    if(ret)
    {
        fprintf(stderr,"%s\n",lua_tostring(L,-1)); //
        lua_pop(L,1);
        return -1;
    }

	//获取想要的表,会自动压栈
	lua_getglobal(L,"paths");

	while(1) {
		lua_pushinteger(L,i++);
		lua_gettable(L,-2);
		if(!lua_isstring(L,-1)) {   
			break;
		}   
		
		str = lua_tostring(L,-1);
		printf("%s\n",str);
		lua_pop(L,1);

		if (dispath(fd,str)) {
			return -1;
		}
	}

	lua_close(L);

    return 0;
}

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

	if (load_config_add_paths(fd,"./config.lua") != 0) {
		printf("load config add path error\n");
		return -1;
	}


	if (hook_funs(fd,__NR_open,__NR_connect,-1) != 0) {
		printf("hook_funs error\n");
		return -1;
	}

#if 0
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
#endif
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
