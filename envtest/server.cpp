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
#include "vsockutils.h"
#include "testcase.h"
#include "mythreads.h"



int main()
{
    std::thread t1{HostThread::connect};
    std::thread t2{HostThread::hook};
    std::thread t3{HostThread::visualize};

    t1.join();
    t2.join();
    t3.join();

    return 0;
}
