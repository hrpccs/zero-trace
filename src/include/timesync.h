#ifndef TIMESYNC_H_
#define TIMESYNC_H_
 
#include <tuple>
#include <chrono>
#include <algorithm>
#include <cereal/archives/binary.hpp>
#include <cereal/types/chrono.hpp>
#include <cereal/types/tuple.hpp>
#include <time.h>

long long getCurrentMonoTime(); 

class timestamps
{
    private:
        long long recvtime;
        long long sendtime;

    public:
        bool regRecvTime();
        bool regSendTime();
        long long getRecvTime();
        long long getSendTime();
        template<class Archive>
        void serialize(Archive & archive)
        {
            archive(recvtime,sendtime); 
        }
};

#endif