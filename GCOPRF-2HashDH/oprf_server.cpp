#include "oprf_server.h"

using namespace std;

const int port = 8888;
const int portNetMeasure = 8890;

// Constructs a vector that contains the bits of block b.
vector<bool>* blockToString(const block& b){
    vector<bool>* s = new vector<bool>();
    uint8_t* data = (uint8_t*) &b; //get the content of block b as bytes 
    for(int j = 0; j < 16; ++j){
        for (int i = 0; i < 8; ++i){
            //msb of each byte is left. lsb is right.
            s->push_back((data[j] >> (7-i)) % 2);
        }
    }
    return s;
}

void measureRuntime(int sid, int nr_rounds){
    // Create Server and OT objects
    NetIO server_io(nullptr, port); // Server is the OT-Sender. 
    vector<bool> zero_key(AES_KEY_SIZE, false); //Test key of 256 0s
    Server<NetIO> s(zero_key, sid, &server_io);
     
    for(int i = 0; i < nr_rounds; ++i){
        block* key = new block[AES_KEY_NR_BLOCKS]; // Block has 128 bits
        PRG prg;
        prg.random_block(key, AES_KEY_NR_BLOCKS);
        //Uncomment the following lines for testing with fixed key 0
        for(int i = 0; i < AES_KEY_NR_BLOCKS; ++i) {
            key[i] = makeBlock(0,0);
        }

        vector<bool> vecKey = *blockToString(key[0]);
        for (int i = 1; i < AES_KEY_NR_BLOCKS; ++ i) {
            vector<bool>* blocki = blockToString(key[i]);
            vecKey.insert(vecKey.end(), blocki->begin(), blocki->end());
        } 
        
        s.setKey(vecKey);
        int ssid = 1;
        vector<bool> decoding_info(AES_INPUT_SIZE);
        vector<block> encoded_key(AES_KEY_SIZE);
        vector<block> encoded_ones(AES_INPUT_SIZE);
        vector<block> encoded_zeroes(AES_INPUT_SIZE);
        s.onGarble(ssid, &encoded_ones, &encoded_zeroes);
    }
    server_io.flush();

}

void measureNetTraffic(int sid){
    NetIO server_io2(nullptr, portNetMeasure); // Server is the OT-Sender. 
    vector<bool> zero_key(AES_KEY_SIZE, false); //Test key of 256 0s
    Server<NetIO> s2(zero_key, sid, &server_io2);
    
    int nr_rounds = 1; 
    for(int i = 0; i < nr_rounds; ++i){
        block* key = new block[2]; // Block has 128 bits
        PRG prg;
        prg.random_block(key, 2);
        //Uncomment the following lines for testing with fixed key 0
        key[0] = makeBlock(0,0);
        key[1] = makeBlock(0,0);
        vector<bool> vecKey = *blockToString(key[0]);
        vector<bool>* block1 = blockToString(key[1]); 
        vecKey.insert(vecKey.end(), block1->begin(), block1->end());

        s2.setKey(vecKey);
        int ssid = 1;
        vector<bool> decoding_info(AES_INPUT_SIZE);
        vector<block> encoded_key(AES_KEY_SIZE);
        vector<block> encoded_ones(AES_INPUT_SIZE);
        vector<block> encoded_zeroes(AES_INPUT_SIZE);
        s2.onGarble(ssid, &encoded_ones, &encoded_zeroes);
    }
}

int main(int argc, char* argv[]){
    int sid = 1;

    //Parse command line argument
    if (argc < 2) {
        cerr << "Wrong number of arguments" << endl;
        return 1;
    }
    int aes_size = atoi(argv[1]);
    if (128 == aes_size) {
        AES_KEY_SIZE = AES_KEY_SIZE_SHORT;
        circuit_filename = circuit_filename_aes128;
    } else if (256 == aes_size) {
        AES_KEY_SIZE = AES_KEY_SIZE_LONG;
        circuit_filename = circuit_filename_aes256;
    } else {
        cerr << "Choose AES 128 or AES 256" << endl;
    }
    AES_KEY_NR_BLOCKS = AES_KEY_SIZE / 64;

    int nr_iterations = atoi(argv[2]);

    measureRuntime(sid, nr_iterations);
    // One round more for the traffic test
    // Need to create new server that connects with the MeasureNetIO class
    measureNetTraffic(sid);
    
}