#include "mesgtype.h"
#include <cstring>
#include <sstream>
#include <string>
#include <iostream>
#include <iomanip>

//void指针并不安全,注意取得数据以后及时转换为安全的类型
#define HELPER_MAKER(TYPE)                                      \
int send_helper_ ## TYPE(void * obj,char *& str)                \
{                                                               \
    TYPE * temp = (TYPE *)obj;                                  \
    std::ostringstream outs0;                                   \
    cereal::BinaryOutputArchive archive(outs0);                 \
    archive(*temp);                                             \
    return genstr(outs0,str);                                   \
}                                                               \
int recv_helper_ ## TYPE(void *& obj,char * str,int len)        \
{                                                               \
    TYPE * temp = new TYPE;                                     \
    std::istringstream ins0(std::string(str,len));              \
    cereal::BinaryInputArchive archive(ins0);                   \
    archive(*temp);                                             \
    obj = (void *)temp;                                         \
    return 1;                                                   \
}


void decode(std::string  str)
{
    for(int i = 0;i < str.length();i++)
    {
        unsigned char j = str[i];
        std::cout << std::hex << std::setw(3) << (unsigned int)(j);
    }
    std::cout << std::endl;
}

static int genstr(std::ostringstream & ostr,char *& str)
{
    int len = ostr.str().length();
    str = new char[len];
    memcpy(str,ostr.str().c_str(),len);
    return len;
}

TYPE_DEF(HELPER_MAKER)
