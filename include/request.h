#ifndef __REQUEST_H__
#define __REQUEST_H__

int login(int fd,const char *user,const char *passwd);

int hook_function(int fd,int sysnum,int ishook);

int dispath(int fd,const char *path,int isenter);

int hook_funs(int fd,int ishook,...);

int dispaths(int fd,int isenter,...);


#endif