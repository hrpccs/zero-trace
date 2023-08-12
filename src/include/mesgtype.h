#ifndef MESGTYPE_H_
#define MESGTYPE_H_

#define SMALL_MESG_LIMIT_BYTES 10   //应该设置为4的倍数
#define TIMEOUT_NS 60000000000LL    //long long类型

#define TYPES 2

//注意:在这里添加完类型以后,还要去vsockutils.cpp的RegisterHelper函数里面修改
#define TYPE_DEF(X) \
    X(timestamps)   \
    X(Request)

#define TYPE_ENUM_MAKER(name) TYPE_ ## name,
enum Type{TYPE_DEF(TYPE_ENUM_MAKER)};


#define TYPE_HELPER_DECLARE(name)                           \
    int send_helper_ ## name(void * obj,char *& str);       \
    int recv_helper_ ## name(void *& obj,char * str,int len);                             
                           
TYPE_DEF(TYPE_HELPER_DECLARE)

#define REGISTER_HELPER(ATYPE,NUM)          \
send_helper[NUM] = send_helper_ ## ATYPE;   \
recv_helper[NUM] = recv_helper_ ## ATYPE;

//注意:因为这里涉及到下标的问题,所以无法直接用通用的方法
//这个部分只能手动一个一个一个写
#define REGISTER_MANY_HELPERS       \
    REGISTER_HELPER(timestamps,0)   \
    REGISTER_HELPER(Request,1)

//注意:这里需要知道所有的类型的头文件
#include "timesync.h"
#include "basic_types.h"

#endif