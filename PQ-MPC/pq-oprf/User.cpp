
#include "User.h"

/*
*Constructs new User with session id sid that connects to  T io. T is the type of the IO Channel.
*/
User::User(int sid, NetIO* netio){
    this->sid = sid;
    io = netio;
}

User::~User(){
    delete io;
}

// Calculates an array of 256 bools from an array of 32 bytes
bool* User::toBoolArray32(uint8_t* a){
    bool* res = new bool[SHA3_OUTPUT_SIZE];
    for (int i = 0; i < 32; ++i){
        for (int j = 0; j < 8; ++j){
            //msb of bytes is left. lsb is right
            res[i*8+j] = (a[i]>>(7-j))%2;
        }

    }
    return res;
}

void sha3_256(uint8_t* output, const uint8_t* msg, int length){
    EVP_MD_CTX *mdctx;
    const EVP_MD *md = EVP_sha3_256();
    unsigned int md_len;

    int res = EVP_Digest(msg, length, output, &md_len, md, NULL);
    if (res != 1) cerr << "Error evalutating SHA 256"<< endl; 
}

/*
Initiates the evaluation of the oprf on password pwd with subession id ssid.
Outputs to cout what the user would send on the network
Returns the 256 bits of the hash of pwd, H_1(pwd) as array 
*/
bool* User::hashInput(string pwd, int ssid){
    // Domain separation tag ensures each subsession has its own hash function
    pwd += std::to_string(sid) + std::to_string(ssid);
    //TODO should ssid really be part of the dst?
    pwd += h_1_suffix;
    //Hash the password using sha3
    uint8_t* input = (uint8_t*) (pwd.c_str()); //TODO better use reinterprete_cast<>
    uint8_t res[SHA3_OUTPUT_SIZE/8];
    sha3_256(res, input, pwd.size());
    return toBoolArray32(res);
}


uint8_t* User::hashOutput(const int ssid, const string pwd, const bool* output){
    string hash_in = "";
    for(int i = 0; i < AES_INPUT_SIZE; i++){
        hash_in += to_string(output[i]);
    }
    hash_in += pwd;
    hash_in += std::to_string(sid)+std::to_string(ssid);
    hash_in += h_2_suffix;
    uint8_t* input = (uint8_t*) (hash_in.c_str()); //TODO better use reinterprete_cast<>
    uint8_t* res = new uint8_t[SHA3_OUTPUT_SIZE/8];
    sha3_256(res, input, hash_in.size());
    return res;
}

uint8_t* User::eval(const int ssid, string pwd){
    bool* hashed_input = hashInput(pwd, ssid);

    bool zero_key[AES_KEY_SIZE];
    Integer a(AES_INPUT_SIZE, hashed_input, BOB);
    // real key will be set by server
    Integer b(AES_KEY_SIZE, zero_key, ALICE);
    Integer c(AES_INPUT_SIZE, (long long) 0, BOB);

    io->sync();
    ProtocolExecution::prot_exec->do_batched_ot();
    
    io->sync();
    cf->compute(c.bits, b.bits, a.bits);

    bool* output = c.reveal<bool*>(BOB);

    return hashOutput(ssid, pwd, output);
}

// appends a string representation of a to out. Array has to have lenght len. Functions is only needed to print the final results to a file
void appendArrayToString(string& out, double* a, int len) {
    out += "[";
    for(int i = 0; i < len-1; ++i){
        out += to_string(a[i]) + ", ";
    }
    if (len > 0)
        out += to_string(a[len-1]);
    out += "]\n";
}



void measureRuntime(int sid, char* ip_address, int port, const string& password, string& output_text, int numIterations){
    double time_stamps[numIterations];
    //Setup everything
    NetIO* netio = new NetIO(ip_address, port);
    User u(sid, netio);
    int ssid = 1;
    u.cf = new CircuitFile(circuit_filename.c_str());
    int total_comm = 0;

    for(int i = 0; i < numIterations; ++i){

        setup_semi_honest(u.io, BOB, AES_INPUT_SIZE + AES_KEY_SIZE);
        
        auto start = std::chrono::high_resolution_clock::now();

        //Actual evaluation            
        uint8_t* prf_output = u.eval(ssid, password);

        auto finish = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = finish - start;

        std::cout << "Elapsed time: " << elapsed.count() << " s\n";
        time_stamps[i] = elapsed.count()*1000; // miliseconds


        // Remember the total communication after one round
        if (i == 0)
            total_comm = netio->get_total_comm();

        //Print result
        cout << std::dec << "THIS IS ROUND " << (i+1) << endl;
        cout << std::hex;
        for(int i = 0; i < SHA3_OUTPUT_SIZE/8; ++i){
            cout << (unsigned int) prf_output[i];
        }
        cout << endl;
        u.io->sync();
    }
    appendArrayToString(output_text, time_stamps, numIterations);

    double avg_time = accumulate(time_stamps, time_stamps+numIterations, 0.0) / numIterations;
    output_text += "Average Time [ms]: " + to_string(avg_time) +"\n";
    //standard deviation
    double variance = 0;
    for(int i = 0; i < numIterations; ++i){
        variance += (time_stamps[i] - avg_time)*(time_stamps[i] - avg_time);
    }
    variance /= numIterations;
    double standard_deviation = sqrt(variance);
    output_text += "Standard Deviation [ms]: " + to_string(standard_deviation) + "\n";
    output_text += ("Measured Traffic total[Bytes]: " + to_string(total_comm) + "\n");

}

int main(int argc, char* argv[]){
    if(argc < 6) {
        cerr << "Not enough arguments provided." << endl;
    } else {
        int sid = atoi(argv[1]);
        //Parse arguments
        string pwd(argv[2]);
        char* ip_address = argv[3];
        int port = atoi(argv[4]);
        cout << "This is the ip address: " << ip_address << endl;
    	int aes_size = atoi(argv[5]);
    	if (aes_size == 128) {
        	AES_KEY_SIZE = AES_KEY_SIZE_SHORT;
        	circuit_filename = circuit_filename_aes128;
    	} else if (aes_size == 256) {
        	AES_KEY_SIZE = AES_KEY_SIZE_LONG;
        	circuit_filename = circuit_filename_aes256;
    	} else {
        	cerr << "Choose AES 128 or AES 256" << endl;
    	}
    	int numIterations = atoi(argv[6]);
        
        //write measurements to a file
        string output_text = "";
        auto t = std::time(nullptr);
        auto tm = *std::localtime(&t);
        char today[11];
        char time_now[9];
        strftime(today, 11, "%Y-%m-%d", &tm);
        strftime(time_now, 9, "%H:%M:%S", &tm);
        output_text = "GC-OPRF benchmark AES " + to_string(AES_KEY_SIZE) +" from " + string(today) + " at " + string(time_now) + " with n = " + to_string(numIterations) + " iterations:\n";
        output_text += "User input: " + pwd + "\n";
        output_text += "-------------------------\n";
        output_text += "Measured time for each run:\n";

        measureRuntime(sid, ip_address, port, pwd, output_text, numIterations);
        string filename = "pq_gcoprf_benchmark_results_aes_" + to_string(AES_KEY_SIZE) + "_";
        strftime(time_now, 9, "%H_%M", &tm);
        filename += string(today) + "_";
        filename += string(time_now);
        filename += ".txt";
        ofstream out(filename);
        out << output_text;
        out.close();
    }

}
