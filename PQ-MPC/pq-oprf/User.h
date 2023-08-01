#ifndef OPRF_USER_HEADER
#define OPRF_USER_HEADER

#include "pq-yao/emp-sh2pc.h"
#include "emp-tool/emp-tool.h"
#include "oprf_utils.h"

#include <cstdint>
#include <openssl/evp.h>

using namespace std;
using namespace emp;


class User{
    
    
    public:
    const string h_1_suffix = "H_1";
    const string h_2_suffix = "H_2";

    int sid;
    NetIO* io;
    CircuitFile* cf;

    /*
    *Constructs new User with session id sid that connects to  T io. T is the type of the IO Channel.
    */
    User(int sid, NetIO* netio);
    ~User();

    // Calculates an array of 256 bools from an array of 32 bytes
    bool* toBoolArray32(uint8_t* a);

    void sha_256(uint8_t* result, const uint8_t* input, int length);

    bool* hashInput(string pwd, int ssid);

    uint8_t* hashOutput(const int ssid, const string pwd, const bool* output);

    uint8_t* eval(const int ssid, string pwd);
};
#endif