#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <unistd.h>

#include "request.h"
#include "messagepro.h"

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

int hook_function(int fd,int sysnum,int ishook)
{
	if (sysnum < 0 || fd < 0) {
		return -1;
	}

	int ret = 0;
	struct messagepro pro[1] = {0};
	pro->type = PROHOOK;
	prohook(pro)->sysnum = sysnum;
	prohook(pro)->ishook = ishook;
	ret = write(fd,pro,MESSLEN);
	if (ret < 0) {
		printf("hook function error\n");
		return -1;
	}

	return 0;
}

int dispath(int fd,const char *path,int isenter)
{
	if (!path || fd < 0) {
		return -1;
	}

	int ret = 0;
	struct messagepro pro[1] = {0};
	pro->type = PROPATH;
	propath(pro)->isenter = isenter;
	memcpy(propath(pro)->path,path,strlen(path));
	ret = write(fd,pro,MESSLEN);
	if (ret < 0) {
		printf("add path error\n");
		return -1;
	}

	return 0;
}

int addkeyword(int fd,const char *keyword,int isenter)
{
	if (!keyword || fd < 0) {
		return -1;
	}

	int ret = 0;
	struct messagepro pro[1] = {0};
	pro->type = PROPATH;
	propath(pro)->isenter = isenter;
	propath(pro)->iskeyword = 1;
	memcpy(propath(pro)->path,keyword,strlen(keyword));
	ret = write(fd,pro,MESSLEN);
	if (ret < 0) {
		printf("add path error\n");
		return -1;
	}

	return 0;
}

int disrewrite(int fd,const char *srcip,const char *objip,int isenter)
{
	if (fd < 0 || !srcip || !objip) {
		return -1;
	}

	int ret = 0;
	struct messagepro pro[1] = {0};
	pro->type = PRODOMAIN;
	prodomain(pro)->enter = isenter;
	prodomain(pro)->rewrite = 1;
	memcpy(prodomain(pro)->srcip,srcip,IPLEN);
	memcpy(prodomain(pro)->objip,objip,IPLEN);
	ret = write(fd,pro,MESSLEN);
	if (ret < 0) {
		printf("add rewrite error\n");
		return -1;
	}

	return 0;
}

int banip(int fd,const char *ip,int isenter)
{
	if (fd < 0 || !ip) {
		return -1;
	}

	int ret = 0;
	struct messagepro pro[1] = {0};
	pro->type = PRODOMAIN;
	prodomain(pro)->enter = isenter;
	prodomain(pro)->ban = 1;
	memcpy(prodomain(pro)->srcip,ip,IPLEN);
	ret = write(fd,pro,MESSLEN);
	if (ret < 0) {
		printf("add bans error\n");
		return -1;
	}

	return 0;
}

int hook_funs(int fd,int ishook,...)
{
	int ret = 0;
	va_list v;
	va_start(v,ishook);

	int num = va_arg(v,int);
	//printf("%d\n",num);
	while (num != -1) {
		ret = hook_function(fd,num,ishook);
		if(ret < 0) return -1;
		num = va_arg(v,int);
		//printf("%d\n",num);
	}

	va_end(v);

	return 0;
}

int dispaths(int fd,int isenter,...)
{
	int ret = 0;
	va_list v;
	va_start(v,isenter);

	char *path = va_arg(v,char *);
	//printf("%s\n",path);
	while (path != NULL) {
		ret = dispath(fd,path,isenter);
		if(ret < 0) return -1;
		path = va_arg(v,char *);
		//if(path != NULL) printf("%s\n",path);
	}

	va_end(v);

	return 0;
}

int disrewrites(int fd,int isenter,...)
{
	int ret = 0;
	va_list v;
	va_start(v,isenter);

	struct ippair *pait = va_arg(v,struct ippair*);
	//printf("%s\n",path);
	while (pait != NULL) {
		ret = disrewrite(fd,pait->srcip,pait->objip,isenter);
		if(ret < 0) return -1;
		pait = va_arg(v,struct ippair*);
		//if(path != NULL) printf("%s\n",path);
	}

	va_end(v);

	return 0;
}