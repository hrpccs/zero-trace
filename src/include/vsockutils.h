#ifndef VSOCKUTILS_H_
#define VSOCKUTILS_H_
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "mesgtype.h"
#include "timesync.h"




class VSockEngine
{
    protected:
        int mysock,sock_client;
        sockaddr_vm myaddr;
        int (* send_helper[TYPES])(void * obj,char *& str);
        int (* recv_helper[TYPES])(void *& obj,char * str,int len);
        int initStreamSock();
        struct sockaddr_vm getBeastAncestorAddr();
        void registerHelpers();
        int sendsmallstr(char * str,enum Type type,int len);
        int sendstr(char * str,enum Type type,int len);
        int recvstr(char *& str,enum Type & type,int & len);
        

    public:
        VSockEngine();
        ~VSockEngine(){}
        int sendMesg(enum Type type,void * obj);
        int recvMesg(enum Type & type,void *& obj);
        long long getDelta();
        int getDeltaHelper();
};

class ClientEngine:public VSockEngine
{
    private:
        int connAddr();

    public:
        ClientEngine();
        ~ClientEngine();

};

class ServerEngine:public VSockEngine
{
    private:
        sockaddr_vm client_addr;
        int bindAddr();
        int listenSock(int len = 5);
        int acceptConn();

    public:
        ServerEngine();
        ~ServerEngine();    
};

#endif