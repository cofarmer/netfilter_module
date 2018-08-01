
//
// Date: 2017-03-27
// Author: Noema
// Description: common.h
// 

#include "./uthash.h"

#ifndef _COMMON_H_
#define _COMMON_H_

#define TCP_SERVER_PORT		6253
#define UDP_SERVER_PORT		6253

#define LOCAL_LISTEN_PORT	6023		// 本地提供服务的端口
#define WEB_PORT			8877		// web端提供服务的端口
#define WEB_LOGIN_PORT		80			// web端提供登录的端口

#define MAX_HISTORY_LINE	100

struct history_info
{
	char domain[256];
	char websiteip[32];
	unsigned long time;
};

// 用于缓存
//
struct client_info
{
	unsigned int		ip;					// client ip address
	unsigned char		mac[6];				// client mac address

	unsigned int		node_ip;			// node ip
	unsigned short		node_port;			// node port
	unsigned int		link_id;			// link id
	unsigned int		user_id;			// user id
	char				key[128];			// key
	char				username[128];		// user name

	unsigned int		his_line_number;
	struct history_info	hisinfo[MAX_HISTORY_LINE];
	unsigned int		active_time;		// network spantime

	// @Noema 增加上下行流量统计

	unsigned long		upflow;				// 
	unsigned long		downflow;			//

	unsigned int		reserved;

	UT_hash_handle		hh;
};

// 用于web端交互
//
struct data_header
{
#define DATA_HEADER_MAGIC 0x7070
	unsigned int magic;

#define OP_NONE						0x1000
#define OP_ADD_CLIENT				OP_NONE + 1
#define OP_DELETE_CLIENT			OP_NONE + 2
#define OP_BROWSER_HISTORY			OP_NONE + 3
#define OP_QUERY_FLOW				OP_NONE + 4
	unsigned int op;
	unsigned int len;
	unsigned int reserved;
	// 后面接数据包
	// JSON数据包
};

#endif // !_COMMON_H_
