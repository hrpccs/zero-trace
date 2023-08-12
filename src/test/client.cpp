#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include <thread>
#include "vsockutils.h"
#include "testcase.h"
#include "mythreads.h"

int runAsClient()
{
    std::thread t1{GuestThread::connect};
    std::thread t2{GuestThread::hook};

    t1.join();
    t2.join();
    
    return 0;
}

/*int main()
{
    return runAsClient();
}*/