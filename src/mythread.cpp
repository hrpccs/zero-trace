#include "mythreads.h"
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include <thread>
#include <iostream>
#include <queue>
#include <mutex>
#include "vsockutils.h"
#include "testcase.h"

namespace HostThread
{
    std::queue<messageexp> from_remote;
    std::queue<messageexp> from_local;
    std::mutex l_remote,l_local;
    
    void connect()
    {
        ServerEngine server;
        while(1)
        {
            Type type;
            void * ptr;
            server.recvMesg(type,ptr);
            //std::cout << "Recv2\n"; 
            if(type == TYPE_timestamps)
            {
                server.getDeltaHelper();
                //std::cout << "Sync\n"; 
            }
            else if(type == TYPE_messageexp)
            {
                //std::cout << "Recv\n";
                messageexp temp = *(messageexp *)ptr;
                //std::cout <<  temp.timestamp << " " << temp.sometalk << std::endl;
                l_remote.lock();
                from_remote.push(temp);
                l_remote.unlock();
            }
        }
    }

    void hook()
    {
        while(1)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(rand() % 1000));
            messageexp temp;
            l_local.lock();
            from_local.push(temp);
            l_local.unlock();
            
        }
        

    }

    void visualize()
    {
        while(1)
        {
            l_remote.lock();
            l_local.lock();
            messageexp temp;

            if(from_local.empty())
            {
                l_local.unlock();
                if(from_remote.empty())
                {
                    l_remote.unlock();
                    continue;
                }
                else
                {
                    temp = from_remote.front();
                    from_remote.pop();
                    l_remote.unlock();
                }
            }
            else
            {
                if(from_remote.empty() || from_remote.front().timestamp > from_local.front().timestamp)
                {
                    l_remote.unlock();
                    temp = from_local.front();
                    from_local.pop();
                    l_local.unlock();
                }
                else 
                {
                    l_local.unlock();
                    temp = from_remote.front();
                    from_remote.pop();
                    l_remote.unlock();
                }
            }

            std::cout << temp.timestamp << " " << temp.sometalk << std::endl;
        }
    }
};

namespace GuestThread
{
    std::queue<messageexp> to_remote;
    std::mutex l_remote;
    long long offset;
    long long lastsync = 0;

    void connect()
    {
        ClientEngine client;
        while(1)
        {
            bool label = 0;
            messageexp temp;
            l_remote.lock();
            if(!to_remote.empty())
            {
                long long cur = getCurrentMonoTime();
                if(cur - lastsync > TIMEOUT_NS)
                {
                    //std::cout << "Sync\n";
                    offset = client.getDelta();
                    lastsync = cur;
                }
                temp = to_remote.front();
                to_remote.pop();
                label = 1;
            }
            l_remote.unlock();
            if(label)
            {
                temp.timestamp -= offset;
                std::cout << temp.timestamp << " " << temp.sometalk << std::endl;
                client.sendMesg(TYPE_messageexp,&temp);
                //std::cout <<"OK\n";
            }
        }
    }

    void hook()
    {
        while(1)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(rand() % 1000));
            messageexp temp;
            l_remote.lock();
            to_remote.push(temp);
            l_remote.unlock();
        }
    }
};