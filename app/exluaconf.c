#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "request.h"

#define DOMAIN      0

static char **domain2ip(const char *domain)
{
    struct hostent *host = gethostbyname(domain);
    if (!host) {
        return NULL;
    }   
 
    if (host->h_addrtype != AF_INET) {
        return NULL;
    }
    
    return host->h_addr_list;
}

static int add_path(int fd,lua_State *L,char *path_name)
{
    if (!L || !path_name) {
        return -1;
    }

    int i = 1;
    const char *str = NULL;
    //获取表
	lua_getglobal(L,path_name);

	while(1) {
        //压入表对应的key
		lua_pushinteger(L,i++);
        //获取key对应的value,并且value压入栈顶
		lua_gettable(L,-2);
		if(!lua_isstring(L,-1)) {   
			break;
		}   
        //从栈顶获取值
		str = lua_tostring(L,-1);
		//printf("%s\n",str);

		lua_pop(L,1);

		if (dispath(fd,str,1)) {
			continue;
		}
	}

    return 0;
}

static int add_hook_function(int fd,lua_State *L,char *hook_name)
{
    if (!L || !hook_name) {
        return -1;
    }

    int i = 1;
    int index,isnum;
    //获取表
	lua_getglobal(L,hook_name);

	while(1) {
        //压入表对应的key
		lua_pushinteger(L,i++);
        //获取key对应的value,并且value压入栈顶
		lua_gettable(L,-2);
		if(!lua_isinteger(L,-1)) { 
            //printf("lua hook quit\n");  
			break;
		}   
        //从栈顶获取值
		index = lua_tointegerx(L,-1,&isnum);
		//printf("index = %d isnum = %d\n",index,isnum);
        if (hook_function(fd,index,1)) {
            continue;
        }

		lua_pop(L,1);
	}

    return 0;
}

static int add_keyword(int fd,lua_State *L,char *keywords)
{
    if (!L || !keywords) {
        return -1;
    }

    int i = 1;
    const char *str = NULL;
    //获取表
	lua_getglobal(L,keywords);

	while(1) {
        //压入表对应的key
		lua_pushinteger(L,i++);
        //获取key对应的value,并且value压入栈顶
		lua_gettable(L,-2);
		if(!lua_isstring(L,-1)) {   
			break;
		}   
        //从栈顶获取值
		str = lua_tostring(L,-1);
		printf("%s\n",str);

		lua_pop(L,1);

		if (addkeyword(fd,str,1)) {
			continue;
		}
	}

    return 0;
}

static int add_domain(int fd,lua_State *L,char *domain)
{
    if (!L || !domain) {
        return -1;
    }

    int i = 1;
    char **ips = NULL;
    const char *str = NULL;
    //获取表
	lua_getglobal(L,domain);

	while(1) {
        //压入表对应的key
		lua_pushinteger(L,i++);
        //获取key对应的value,并且value压入栈顶
		lua_gettable(L,-2);
		if(!lua_isstring(L,-1)) {   
			break;
		}   
        //从栈顶获取值
		str = lua_tostring(L,-1);
		printf("%s\n",str);

		lua_pop(L,1);

        ips = domain2ip(str);
        if (ips == NULL) {
            printf("domain to ip error\n");
            continue;
        }

        for (int i=0; ips[i]; i++) {
            if (banip(fd,inet_ntoa(*(struct in_addr*)ips[i]),1)) {
                continue;
            }
        }
	}

    return 0;
}

static int addr_rewrite(int fd,lua_State *L,char *rewrite_name)
{
    if (!L || !rewrite_name) {
        return -1;
    }

    int i = 1;
    int j = 0;
    int index = 0;
    int size = 0;
    const char *str1 = NULL;
    const char *str2 = NULL;
    char **ips1 = NULL;
    char **ips2 = NULL;
    char (*data)[IPLEN] = NULL;

    lua_getglobal(L,rewrite_name);

    while(1) {
        lua_pushinteger(L,i++);
        lua_gettable(L,-2);
		if(!lua_istable(L,-1)) { 
            //printf("lua rewrite quit\n");  
			break;
		}

        lua_pushinteger(L,1);
        lua_gettable(L,-2);
        if(!lua_isstring(L,-1)) { 
            //printf("-- lua rewrite quit\n");  
			break;
		}

        str1 = lua_tostring(L,-1);
        printf("%s -->",str1);
#if DOMAIN
        ips1 = domain2ip(str1);
        for (j = 0;ips1[j];j++) {
            size++;
        }
        printf("size = %d\n",size);
        data = calloc(1,IPLEN * size);
        for (j = 0;ips1[j];j++) {
            memcpy(data[j],inet_ntoa(*(struct in_addr*)ips1[j]),IPLEN);
        }
#endif
        lua_pop(L,1);

        lua_pushinteger(L,2);
        lua_gettable(L,-2);
        if(!lua_isstring(L,-1)) { 
            //printf("-- lua rewrite quit\n");  
			break;
		}

        str2 = lua_tostring(L,-1);
        printf("%s\n",str2);
#if DOMAIN
        ips2 = domain2ip(str2);
#endif
        lua_pop(L,1);
#if DOMAIN
        for (j = 0;j < size;j++) {
            printf("%s --> %s\n",data[j],inet_ntoa(*(struct in_addr*)ips2[0]));
            disrewrite(fd,data[j],inet_ntoa(*(struct in_addr*)ips2[0]),1);
        }
#else
        disrewrite(fd,str1,str2,1);
#endif
        lua_pop(L,1);
        free(data);
    }

    return 0;
}

int load_config(int fd,const char *confpath)
{
    if (fd < 0 || !confpath) {
        return -1;
    }

    //初始化lua环境
    lua_State *L = luaL_newstate();
    luaL_openlibs(L);
	//编译并执行
    int ret = luaL_loadfile(L,confpath) || lua_pcall(L,0,0,0);
    if(ret)
    {
        fprintf(stderr,"%s\n",lua_tostring(L,-1));
        lua_pop(L,1);
        return -1;
    }

    add_path(fd,L,"paths");
    add_hook_function(fd,L,"hook_functions");
    add_domain(fd,L,"domains");
    addr_rewrite(fd,L,"rewrites");
    add_keyword(fd,L,"keywords");

	lua_close(L);

    return 0;
}