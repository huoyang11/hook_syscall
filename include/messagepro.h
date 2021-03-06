#ifndef __MESSAGEPRO_H__
#define __MESSAGEPRO_H__

#define PROLOGIN	(1<<1)
#define PROHOOK		(1<<2)
#define PRODISDIR	(1<<3)
#define PROENDIR	(1<<4)
#define PRODISFILE	(1<<5)
#define PROENFILE	(1<<6)
#define PROREWRITE	(1<<7)

#define PROPATH		(PRODISDIR | PROENDIR | PRODISFILE | PROENFILE)

#define USERLEN		10
#define PASSWDLEN	10

struct message_login{
	char user[USERLEN];
	char passwd[PASSWDLEN];
};

struct message_hook{
	int sysnum;
	int ishook;
};

#define PATHMAX		512

struct message_path{
	unsigned int isdis:1;
	unsigned int isfile:1;
	unsigned int isenter:1;
	char path[PATHMAX];
};

#define IPLEN	16

struct message_rewrite{
	int  enter;
	char srcip[IPLEN];
	char objip[IPLEN];
};

#define prologin(pro)	(&((pro)->data.login))
#define prohook(pro)	(&((pro)->data.hook))
#define propath(pro)	(&((pro)->data.path))
#define prorewrite(pro) (&((pro)->data.rewrite))

#define islogin(pro)	((pro)->type & PROLOGIN)
#define ishook(pro)		((pro)->type & PROHOOK)
#define ispath(pro)		((pro)->type & PROPATH)
#define isrewrite(pro)	((pro)->type & PROREWRITE)

#define MESSLEN			(sizeof(struct messagepro))

struct messagepro{
	unsigned int type;
	union{
		struct message_login login;
		struct message_hook hook;
		struct message_path path;
		struct message_rewrite rewrite;
	}data;
};

#endif
