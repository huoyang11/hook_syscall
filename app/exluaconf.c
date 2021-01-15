#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <string.h>

#include "request.h"

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
			return -1;
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
            return -1;
        }

		lua_pop(L,1);
	}

    return 0;
}

static int addr_rewrite(int fd,lua_State *L,char *rewrite_name)
{
    if (!L || !rewrite_name) {
        return -1;
    }

    int i = 1;
    int index = 0;
    const char *str = NULL;
    struct ippair ipp;

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

        str = lua_tostring(L,-1);
        memcpy(ipp.srcip,str,strlen(str)+1);
        printf("%s -->",str);
        lua_pop(L,1);

        lua_pushinteger(L,2);
        lua_gettable(L,-2);
        if(!lua_isstring(L,-1)) { 
            //printf("-- lua rewrite quit\n");  
			break;
		}

        str = lua_tostring(L,-1);
        memcpy(ipp.objip,str,strlen(str)+1);
        printf("%s \n",str);
        lua_pop(L,1);

        if (disrewrite(fd,ipp.srcip,ipp.objip,1)) {
            return -1;
        }

        lua_pop(L,1);
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
    addr_rewrite(fd,L,"rewrites");

	lua_close(L);

    return 0;
}