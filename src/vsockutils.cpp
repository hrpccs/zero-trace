#include "vsockutils.h"
#include <iostream>
#include <stdlib.h>
#include <iomanip>

int VSockEngine::initStreamSock()
{
    mysock = socket(AF_VSOCK, SOCK_STREAM, 0);

    if(-1 == mysock)
    {
        fprintf(stderr,"socket error\n");
        abort();
    }
    return mysock;
}


struct sockaddr_vm VSockEngine::getBeastAncestorAddr()
{
    memset(&myaddr, 0, sizeof(myaddr));
    myaddr.svm_family = AF_VSOCK;
    myaddr.svm_cid = VMADDR_CID_HOST;
    myaddr.svm_port = htons(11451); //henghengheng,aaaaaaaaaaaaaaa
    return myaddr;
}


void VSockEngine::registerHelpers()
{
    REGISTER_MANY_HELPERS
}




int VSockEngine::sendstr(char * str,enum Type type,int len)
{
    int header[2 + SMALL_MESG_LIMIT_BYTES / 4];
    header[0] = type;
    header[1] = len;

    size_t len1 = sizeof(header);
    if(len <= SMALL_MESG_LIMIT_BYTES)
    {
        memcpy(header + 2,str,len);
    }

    int ret= write(sock_client, (void *)header, len1);
    if(ret != len1)
    {
        fprintf(stderr,"write header error\n");
        abort();
    }
    
    

    if(len > SMALL_MESG_LIMIT_BYTES)
    {
        ret = write(sock_client, (void *)str, len);
        if(ret != len)
        {
            fprintf(stderr,"write error\n");
            abort();
        }
    }
    

    return ret;
}

int VSockEngine::recvstr(char *& str,enum Type & type,int & len)
{
    int header[2 + SMALL_MESG_LIMIT_BYTES / 4];
    size_t len1 = sizeof(header);
    int ret = recv(sock_client, (void *)header, len1, 0); 
    if(ret != len1)
    {
        fprintf(stderr,"read header error\n");
        abort();
    }

    type = (enum Type)header[0];
    len = header[1];
    str = new char[len];
    if(len <= SMALL_MESG_LIMIT_BYTES)
    {
       memcpy(str,header + 2,len);
    }
    
    else
    {
        ret = recv(sock_client, (void *)str, len, 0); 
        if(ret != len)
        {
            fprintf(stderr,"read error\n");
            abort();
        }

    
    }
    return ret; 
}

VSockEngine::VSockEngine()
{
    initStreamSock();
    getBeastAncestorAddr();
    registerHelpers();
}




//sendhelper:Covert data to string,return string length
//int helper(std::any obj,char *& str)
//recvhelper:Covert string to data
//int helper(std::any & obj,char * str)

void decodec(char * buf,int len)
{
    for(int i = 0;i < len;i++)
    {
        unsigned char j = buf[i];
        std::cout << std::hex << std::setw(3) << (unsigned int)(j);
    }
    std::cout << std::endl;
}


int VSockEngine::sendMesg(enum Type type,void * obj)
{
    char * buf;
    int actural_len = send_helper[type](obj,buf); //生成字符串,因为类里面可能有指针,导致直接强转会出问题
    int sent_len = sendstr(buf,type,actural_len);
    return sent_len;
}

int VSockEngine::recvMesg(enum Type & type,void *& obj)
{
    char * buf;
    int len;
    recvstr(buf,type,len);
    //std::cout << "Recvstr\n";
    return recv_helper[type](obj,buf,len);
}

//返回本机时间-远端时间
long long VSockEngine::getDelta()
{
    timestamps mesg;
    void * ptr = &mesg;    
    long long mysend = getCurrentMonoTime();
    //std::cout << mysend << std::endl;
    sendMesg(TYPE_timestamps,ptr);
    Type temp;
    recvMesg(temp,ptr);
    mesg = *(timestamps *)ptr;
    long long myrecv = getCurrentMonoTime();
    //std::cout << mesg.getRecvTime() << std::endl;
    //std::cout << mesg.getSendTime() << std::endl;
    //std::cout << myrecv << std::endl;
    long long d2 = (myrecv - mesg.getSendTime());
    long long d1 = (mysend - mesg.getRecvTime());
    return (d1 + d2) / 2;
}

int VSockEngine::getDeltaHelper()
{
    timestamps mesg;
    mesg.regRecvTime();
    //std::cout << mesg.getRecvTime() << std::endl;
    mesg.regSendTime();
    //std::cout << mesg.getSendTime() << std::endl;
    return sendMesg(TYPE_timestamps,&mesg);
}

int ClientEngine::connAddr()
{
    int ret = connect(mysock,(sockaddr *)&myaddr, sizeof(sockaddr_vm));
    if(ret < 0) 
    {
        fprintf(stderr,"connect error");
        abort();
    }
    return ret;
}

ClientEngine::ClientEngine():VSockEngine()
{
    connAddr();
    sock_client = mysock;
}

ClientEngine::~ClientEngine()
{
    close(mysock);
}

int ServerEngine::bindAddr()
{
    int ret = bind(mysock,(sockaddr *)&myaddr, sizeof(sockaddr_vm));
    if(ret < 0) 
    {
        fprintf(stderr,"bind error");
        abort();
    }
    return ret;
}

int ServerEngine::listenSock(int len)
{
    int ret = listen(mysock, 5);
    if(ret < 0) 
    {
        fprintf(stderr,"listen error");
        abort();
    }
    return ret;
}

int ServerEngine::acceptConn()
{
    socklen_t len = sizeof(client_addr);
    sock_client = accept(mysock,(struct sockaddr*)&client_addr, &len);

    if(-1 == sock_client)
    {
        fprintf(stderr,"accept error");
        abort();
    }
    return sock_client;
}

ServerEngine::ServerEngine():VSockEngine()
{
    bindAddr();
    listenSock();
    acceptConn();
}

ServerEngine::~ServerEngine()
{
    close(mysock);
    close(sock_client);
} 