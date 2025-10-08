
#ifndef DSSE_PARAM_H
#define DSSE_PARAM_H

//#define INTEL_AES_NI                        // Intel AES-NI library

#define VARIANT_II                           // 4 options: VARIANT_MAIN, VARIANT_I, VARIANT_II, VARIANT_III
#define DISK_STORAGE_MODE                 // Enable to store Encrypted index on HDD (RAM if disabled)
#define SEND_SEARCH_FILE_INDEX              // Search result contains specific file indexes

#define PEER_ADDRESS "tcp://localhost:5555"




#define  MAX_NUM_OF_FILES 8192              // maximum number of keywords, should be power of 2 and divisible by 8
#define  MAX_NUM_KEYWORDS 72155             // maximum number of files



#define BLOCK_STATE_PIECE_COL_SIZE (NUM_BLOCKS/BYTE_SIZE) //20       // in byte

#define MATRIX_PIECE_COL_SIZE  128           //in byte, set this to split into submatrices in case the whole encrypted index is too large




#include "DSSE_Hashmap_Key_Class.h"	
#include <stdio.h>
#include <stdlib.h>
#include <cerrno>								
#include <algorithm>						
#include <functional>						
#include <iostream>						
#include <fstream>	
#include <sstream>	
#include <bitset>
#include <vector>
#include <iterator>	
#include <dirent.h>	
#include <sys/types.h>			
#include <sys/stat.h>		
#include <unistd.h>
#include <set>												
#include <sparsehash/dense_hash_map>				
#include <boost/algorithm/string/split.hpp>		
#include <boost/algorithm/string.hpp>
#include "climits"
#include <chrono>
#include "tomcrypt.h"
#include "string.h"
#include <unordered_map>


const std::string SERVER_PORT = "5555";


const std::string seed = "12345678";             //random seed



#if defined(VARIANT_MAIN)
    #define ENCRYPT_BLOCK_SIZE 1              // Variant I in bit and should be either 1,2,4 or divisable by 8 and not larger than 128
    
#elif defined(VARIANT_I) 
    #define ENCRYPT_BLOCK_SIZE 128              // Variant I in bit and should be either 1,2,4 or divisable by 8 and not larger than 128
    
#elif defined(VARIANT_II)
    #define DECRYPT_AT_CLIENT_SIDE            

    #define ENCRYPT_BLOCK_SIZE 1              // Variant I in bit and should be either 1,2,4 or divisable by 8 and not larger than 128
 
#elif defined(VARIANT_III)
    #define DECRYPT_AT_CLIENT_SIDE             

    #define ENCRYPT_BLOCK_SIZE 128              // Variant I in bit and should be either 1,2,4 or divisable by 8 and not larger than 128
 
#endif

static const string gcsDataStructureFilepath = "../data/state/";
static const string gcsMatrixPiecePath = "../data/EIDX/";


static const string gcsFilepath = "../data/DB/";			                // path of input database

static const string gcsUpdateFilepath = "../data/Update/";			        // Path of updated file
static const string gcsEncryptedFileCollection = "EncryptedFileCollection.dat";			        // Path of ciphertext

// MODIFIKASI: Tambahkan path untuk server menyimpan file terenkripsi
static const string gcsServerEncryptedFilesPath = "..data/encrypted_files/";


#define MATRIX_PIECE_ROW_SIZE MATRIX_ROW_SIZE //in bit
#define BLOCK_STATE_PIECE_ROW_SIZE MATRIX_PIECE_ROW_SIZE    
#define BLOCK_STATE_ROW_SIZE MATRIX_ROW_SIZE

#define COL 1
#define ROW 2
using namespace std;	
using google::dense_hash_map;
using namespace boost::algorithm;

#define ZERO_VALUE 0
#define ONE_VALUE 1	

#define BYTE_SIZE 8	
#define TRAPDOOR_SIZE 16   
#define BLOCK_CIPHER_SIZE 16
															


//Loading factors in hash table before resizing
#define FILE_LOADING_FACTOR 0.5
#define KEYWORD_LOADING_FACTOR 0.5



#define MATRIX_COL_SIZE ((MAX_NUM_OF_FILES/BYTE_SIZE))	
#define NUM_BLOCKS (MAX_NUM_OF_FILES/ENCRYPT_BLOCK_SIZE)	
#define MATRIX_ROW_SIZE MAX_NUM_KEYWORDS


//Commands for Client - Server interaction
#define CMD_SEND_DATA_STRUCTURE          0x000010
#define CMD_LOADSTATE                    0x000011
#define CMD_SAVESTATE                    0x000012
// #define CMD_SETUP_UPLOAD_ENCRYPTED_FILES 0x000013 // Perintah ini tidak lagi digunakan, diganti dengan yang lebih spesifik
#define CMD_ADD_FILE_OPERATION           0x000014
#define CMD_DELETE_FILE_OPERATION        0x000015

// MODIFIKASI: Perintah baru untuk mengirim satu file terenkripsi saat setup
#define CMD_SETUP_SEND_ENCRYPTED_FILE    0x000016 
#define CMD_REQUEST_ENCRYPTED_FILE       0x000017 // Perintah baru untuk dekripsi

#define CMD_SEARCH_OPERATION             0x000020
#define CMD_REQUEST_BLOCK_DATA           0x000050
#define CMD_REQUEST_SEARCH_DATA          0x000051
#define CMD_UPDATE_BLOCK_DATA            0x000060
#define CMD_SUCCESS                      "CMD_OK"

//define the default filename of some data structures in DSSE scheme
#define FILENAME_BLOCK_STATE_MATRIX     "block_state_mat"
#define FILENAME_BLOCK_COUNTER_ARRAY     "block_counter_arr"
#define FILENAME_KEYWORD_COUNTER_ARRAY     "keyword_counter_arr"
#define FILENAME_TOTAL_KEYWORDS_FILES     "keywords_files"
#define FILENAME_SEARCH_RESULT          "search_result"

static const string gcsKwHashTable = "kw_hashtable";
static const string gcsFileHashTable = "file_hashtable";
static const string gcsListFreeFileIdx = "lstFreeFileIdx";
static const string gcsListFreeKwIdx = "lstFreeKwIdx";


#define KEYWORD_NOT_EXIST MAX_NUM_KEYWORDS+1
#define FILE_NOT_EXIST MAX_NUM_OF_FILES+1

//buffer size of each packet for sending / receiving 
#define SOCKET_BUFFER_SIZE              256

//MACROS
#define BIT_READ(character, position, the_bit)	((*the_bit = *character & (1 << position)))	
#define BIT_SET(character, position) ((*character |= 1 << position))	
#define BIT_CLEAR(character, position) ((*character &= ~(1 << position)))
#define BIT_TOGGLE(character, position)	((*character ^= 1 << position))
#define BIT_CHECK(var,pos) !!((*var) & (1<<(pos)))


// Delimiter separating unique keywords from files 		
const char* const delimiter = "`-=[]\\;\',./~!@#$%^&*()+{}|:\"<>? \n\t\v\b\r\f\a";	
												
typedef unsigned long long int TYPE_COUNTER;
typedef unsigned long long int TYPE_INDEX;
typedef dense_hash_map<hashmap_key_class,TYPE_INDEX,hashmap_key_class,hashmap_key_class> TYPE_GOOGLE_DENSE_HASH_MAP;
typedef set<string> TYPE_KEYWORD_DICTIONARY;
typedef std::unordered_map<TYPE_INDEX, std::string> TYPE_ENC_FILE_MAP;

static TYPE_KEYWORD_DICTIONARY keywords_dictionary;

#define time_now std::chrono::high_resolution_clock::now()



#endif
