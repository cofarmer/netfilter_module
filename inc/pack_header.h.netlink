
//
// Date: 2017-03-27
// Author: Noema
// Description: pack_header.h
// 

#ifndef _PACK_HEADER_H_
#define _PACK_HEADER_H_


struct _flow_tuple 
{
	unsigned short sport;
	unsigned short dport;
	unsigned int saddr;
	unsigned int daddr;
};

struct nl_data
{
	struct _flow_tuple ftuple;
	unsigned char src_mac[6];
};

// payload header
struct _msg_header 
{
	unsigned char direction;
	unsigned char reserved;
	unsigned short tunnel;
	struct _flow_tuple flowtuple;
};


#define  D_MAGIC		0x7070

#pragma pack(push, 1)
struct _dest_info 
{
	unsigned int magic; 
	unsigned int length;
	unsigned int daddr;
	unsigned short dport;
	unsigned char src_mac[6];
	unsigned short reserved;
};
#pragma pack(pop)


#endif // !_PACK_HEADER_H_
