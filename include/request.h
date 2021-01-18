#ifndef __REQUEST_H__
#define __REQUEST_H__

#include "messagepro.h"

struct ippair
{
    char srcip[IPLEN];
    char objip[IPLEN];
};


int login(int fd,const char *user,const char *passwd);

int hook_function(int fd,int sysnum,int ishook);

int dispath(int fd,const char *path,int isenter);

int addkeyword(int fd,const char *keyword,int isenter);

int disrewrite(int fd,const char *srcip,const char *objip,int isenter);

int hook_funs(int fd,int ishook,...);

int dispaths(int fd,int isenter,...);


#endif