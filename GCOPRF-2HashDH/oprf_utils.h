#ifndef OPRF_UTILS
#define OPRF_UTILS
#include <string>

const int AES_INPUT_SIZE = 128;
const int AES_KEY_SIZE_SHORT = 128;
const int AES_KEY_SIZE_LONG = 256;
const int SHA3_OUTPUT_SIZE = 256;
int AES_KEY_SIZE;
int AES_KEY_NR_BLOCKS;

const std::string gc_filename = "bin/garbled_aes_from_oprf.txt";
const std::string circuit_filename_aes128 = "emp-tool/emp-tool/circuits/files/bristol_format/AES-non-expanded.txt";
const std::string circuit_filename_aes256 = "./aes_256_bristol_format.txt";
std::string circuit_filename;

#endif