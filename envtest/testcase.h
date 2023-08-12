#ifndef TESTCASE_H_
#define TESTCASE_H_
#include <string>
#include <vector>
#include <memory>
#include <algorithm>
#include <cereal/archives/binary.hpp>
#include <cereal/types/string.hpp>
#include <cereal/types/memory.hpp>
#include <cereal/types/vector.hpp>
#include <cstdlib>

#include "timesync.h"

class example0
{
    private:
        std::string str;
    public:
        std::string & get(){return str;}
        const std::string & get()const{return str;}
        template<class Archive>
        void serialize(Archive & archive)
        {
            archive(str); 
        }
        

};

class example1
{
    private:
        std::vector<example0> strvec;
        int data;
    public:
        std::vector<example0> & getvec(){return strvec;}
        int & getdata(){return data;}
        template<class Archive>
        void serialize(Archive & archive)
        {
            archive(strvec,data); 
        }
};

class example2:public example1
{
    private:
        std::unique_ptr<double> ptr;
    public:
        
        example2():example1(){ptr = std::make_unique<double>(1.14514);}
        double getdouble(){return *ptr.get();}
        template <class Archive>
        void serialize( Archive & ar )
        {  
            ar( cereal::base_class<example1>( this ), ptr ); 
        }
};



class messageexp
{
    public:
        long long timestamp;
        std::string sometalk;
    public:
        messageexp()
        {
            char testbuf[70];
            timestamp = getCurrentMonoTime();
            int len = rand() % 65 + 1;
            for(int i = 0;i < len;i++)
            {
                testbuf[i] = 'A' + rand() % 26;
            }
            testbuf[len] = 0;
            sometalk = testbuf;
        }
        template <class Archive>
        void serialize( Archive & ar )
        {  
            ar(timestamp,sometalk); 
        }
};

#endif