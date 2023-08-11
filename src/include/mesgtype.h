#ifndef MESGTYPE_H_
#define MESGTYPE_H_
#define TYPES 6
#define SMALL_MESG_LIMIT_BYTES 10   //应该设置为4的倍数
#define TIMEOUT_NS 60000000000LL    //long long类型

//注意:在这里添加完类型以后,还要去vsockutils.cpp的RegisterHelper函数里面修改
#define TYPE_DEF(X) \
    X(example0)     \
    X(example1)     \
    X(example2)     \
    X(timestamps)   \
    X(messageexp)   \
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
#define REGISTER_MANY_HELPERS   \
REGISTER_HELPER(example0,0)     \
REGISTER_HELPER(example1,1)     \
REGISTER_HELPER(example2,2)     \
REGISTER_HELPER(timestamps,3)   \
REGISTER_HELPER(messageexp,4)   \
REGISTER_HELPER(Request,5)

//注意:这里需要知道所有的类型的头文件
#include "testcase.h"
#include "timesync.h"
#include "basic_types.h"

#endif