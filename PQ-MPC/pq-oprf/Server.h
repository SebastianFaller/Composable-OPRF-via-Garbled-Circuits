#ifndef OPRF_USER_HEADER
#define OPRF_USER_HEADER

#include "pq-yao/emp-sh2pc.h"
#include "emp-tool/emp-tool.h"
#include "oprf_utils.h"

using namespace std;
using namespace emp;

class Server{
    public:
        const string h_1_suffix = "H_1";
        const string h_2_suffix = "H_2";

        int sid;
        NetIO* io;
        CircuitFile* cf;
        
        bool* key;
    /*
    *Constructs new Server with session id sid that connects to  T io. T is the type of the IO Channel.
    */
    Server(int sid, int port);

    // Calculates an array of 256 bools from an array of 32 bytes
    bool* toBoolArray32(uint8_t* a);

    bool* initKey();


    void serverCmplt(const int ssid);
};

#endif