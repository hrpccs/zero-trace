#include "timesync.h"

long long getCurrentMonoTime()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return 1000000000 * ts.tv_sec + ts.tv_nsec;
}

bool timestamps::regRecvTime()
{
    recvtime = getCurrentMonoTime();
    return 1;
}

bool timestamps::regSendTime()
{
    sendtime = getCurrentMonoTime();
    return 1;
}

long long timestamps::getRecvTime()
{
    return recvtime;
}
long long timestamps::getSendTime()
{
    return sendtime;
}