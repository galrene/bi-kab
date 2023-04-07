#ifndef __PROGTEST__
#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>

#endif /* __PROGTEST__ */

#define HASH_SIZE EVP_MAX_MD_SIZE

class CHasher {
private:
    const EVP_MD * m_HashFuncType;
    EVP_MD_CTX * m_Ctx;

    unsigned char * m_Hash;
    unsigned int m_HashLength;
    int m_MaxHashSize;
public:
    explicit CHasher ( int hashSize )
    : m_HashFuncType ( EVP_sha512() ), m_Ctx ( NULL ), m_Hash ( NULL ), m_HashLength ( 0 ), m_MaxHashSize ( hashSize ) {}
    CHasher ( int hashSize, const EVP_MD * hashFunc )
    : m_HashFuncType ( hashFunc ), m_Ctx ( NULL ), m_Hash ( NULL ), m_HashLength ( 0 ), m_MaxHashSize ( hashSize ) {}
    ~CHasher() {
        if ( m_Ctx )
            EVP_MD_CTX_free ( m_Ctx );
        if ( m_Hash )
            free ( m_Hash );
    }
    /**
    * Create and initialise context, allocate memory for hash.
    * @return 1 success, 0 fail
    */
    bool alloc ();
    /**
     * Calculate the hash from fed message.
     * @return hash on success, NULL on failure
     */
    unsigned char * final();
    /**
     * Get the stored hash calculated by final().
     * @return hash on success, NULL when no hash calculated yet
     */
    unsigned char * getHash() { return m_Hash; }
    unsigned int getHashLen() { return m_HashLength; }

    /**
     * Feed text to hashing function.
     * @param text
     * @param size length of text excluding \0
     * @return true success, false failure
     */
    bool update ( char * text, size_t size );
    /**
     * Initialise the hashing function.
     */
    bool init();
};

bool CHasher::update ( char * text, size_t size ) {
    // feed message to function
    if ( ! EVP_DigestUpdate ( m_Ctx, text, size ) ) {
        printf("Failed to feed the message.\n");
        return false;
    }
    return true;
}

unsigned char * CHasher::final () {
    // get the hash
    if ( ! EVP_DigestFinal_ex ( m_Ctx, m_Hash, &m_HashLength ) ) {
        printf("Failed to finalize the hash.\n");
        return NULL;
    }
    return m_Hash;
}

bool CHasher::init() {
    if ( ! EVP_DigestInit_ex( m_Ctx, m_HashFuncType, NULL ) ) {
        printf( "Digest setup failed.\n");
        return false;
    }
    return true;
}

bool CHasher::alloc () {
    if ( m_Ctx = EVP_MD_CTX_new(); m_Ctx == NULL ) {
        printf("Context creation/initialisation failed.\n");
        return false;
    }
    m_Hash = ( unsigned char * ) calloc ( m_MaxHashSize, sizeof ( unsigned char ) );
    if ( ! m_Hash ) {
        printf( "Hash allocation failed.\n");
        return false;
    }
    return true;
}
/**
 * Convert hex num represented as a character to it's hexadecimal value.
 */
unsigned char charToHex ( unsigned char c ) {
    if ( c > 'F' || ( c < 'A' && c >'9' ) || c < '0' )
        return 0;
    if ( c >= 'A' )
        return c - 55;
    return c - '0';
}

bool foundMessage ( const int bits, const unsigned char * hash, const size_t hashLength ) {
    if ( ! hash || hashLength <= 0 || bits < 0  )
        return false;
    int zeroBitCounter = 0;
    for ( size_t i = 0; i < hashLength; i++ ) {
        unsigned char word = hash[i];
        for ( int j = 0; j < 8; j++ ) {
             if ( ( word & 0b10000000 ) != 0 )
                return zeroBitCounter >= bits;
            zeroBitCounter++;
            word <<= 1;
        }
    }
    return zeroBitCounter >= bits;
}

/**
 * Converts c string of strlen() == srcLen to a hexadecimal std::string.
 */
std::string convertToHex ( const char * src, size_t srcLen ) {
    std::stringstream ss;
    for ( size_t i = 0; i < srcLen; i++ )
        ss << std::setfill('0') << std::setw(2) << std::hex <<  ( unsigned int ) ( unsigned char ) src[i];
    return ss.str();
}
/**
 * Send size bytes from src to dst, allocate dst on the heap.
 * @return false if src or dst null or allocation failed
 */
bool sendBytesAsHex ( const char * src, char ** dst, size_t size ) {
    if ( ! src || ! dst )
        return false;
    std::string hexMsg = convertToHex(src, size);
    *dst = ( char * ) malloc ( hexMsg.size() + 1 );
    if ( ! *dst ) {
        free(*dst);
        return false;
    }
    memcpy( *dst, hexMsg.c_str(), hexMsg.size() + 1 );
    return true;
}
/**
 * Find message whose hash starts with bits amount of zeroes.
 * @param bits requested length of 0 prefix
 * @param message output found message
 * @param hash hash of message starting with bits amount of 0's
 * @return 1 if success, 0 if fail or wrong parameters
 */
int findHashEx (int bits, char ** message, char ** hash, const char * hashFunction) {
    const EVP_MD * hashFuncType = EVP_get_digestbyname(hashFunction);
    if ( ! hashFuncType || bits < 0 || bits > EVP_MD_size(hashFuncType) || message == NULL || hash == NULL )
        return 0;
    CHasher hf ( HASH_SIZE, hashFuncType );
    if ( ! hf.alloc() )
        return 0;

    /* such size because the hash is going to be recycled as the new message */
    char mess [HASH_SIZE] = {0};
    RAND_bytes (reinterpret_cast<unsigned char *>(mess), HASH_SIZE );

    while ( true ) {
        if ( ! hf.init () || ! hf.update(mess, HASH_SIZE) || ! hf.final() )
            return 0;
        if ( foundMessage ( bits, hf.getHash(), hf.getHashLen() ) )
            break;
        memcpy ( mess, hf.getHash(), HASH_SIZE ); // use the next message as the previously generated hash
    }

    if ( ! sendBytesAsHex(mess, message, HASH_SIZE ) ||
         ! sendBytesAsHex (reinterpret_cast<const char *>(hf.getHash()), hash, hf.getHashLen() ) )
        return 0;

    return 1;
}
/**
 * findHashEx using sha512
 */
int findHash ( int bits, char ** message, char ** hash ) {
    return findHashEx ( bits, message, hash, "sha512" );
}

#ifndef __PROGTEST__
using namespace std;

int checkHash ( int bits, char * hexString ) {
    int zeroBitCounter = 0;
    for ( size_t i = 0; i < 128; i++ ) {
        unsigned char word = charToHex ( hexString[i] );
        for ( int j = 0; j < 4; j++ ) {
            if ( ( word & 0b00001000 ) != 0 )
                return zeroBitCounter >= bits;
            zeroBitCounter++;
            word <<= 1;
        }
    }
    return zeroBitCounter >= bits;
}
#include <chrono>

int main () {
    char * message, * hash;
    vector<pair<int,int>> durs;
    for ( int i = 0 ; i < 15; i++ ) {
        auto start = std::chrono::high_resolution_clock::now();
        findHash ( i, &message, &hash );
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        durs.emplace_back ( i, duration.count() );
        std::cout << i << " zeroes time: " << duration.count() << "us" << std::endl;
        free (message);
        free (hash);
    }
    cout << "{";
    for ( auto it = durs.begin(); it != durs.end(); ++it ) {
        cout << "{" << it->first << "," << it->second << "}";
        if ( it != --durs.end() )
            cout << ",";
    }
    cout << "}";
//
//
//    assert(findHash(0, NULL, NULL) == 0);
//    assert(findHash(0, &message, &hash) == 1);
//    assert(message && hash && checkHash(0, hash));
//    free(message);
//    free(hash);
//    assert(findHash(1, &message, &hash) == 1);
//    assert(message && hash && checkHash(1, hash));
//    free(message);
//    free(hash);
//    assert(findHash(2, &message, &hash) == 1);
//    assert(message && hash && checkHash(2, hash));
//    free(message);
//    free(hash);
//    assert(findHash(3, &message, &hash) == 1);
//    assert(message && hash && checkHash(3, hash));
//    free(message);
//    free(hash);
//    assert(findHash(4, &message, &hash) == 1);
//    assert(message && hash && checkHash(4, hash));
//    free(message);
//    free(hash);
//    assert(findHash(16, &message, &hash) == 1);
//    assert(message && hash && checkHash(16, hash));
//    free(message);
//    free(hash);
//    assert(findHash(20, &message, &hash) == 1);
//    assert(message && hash && checkHash(20, hash));
//    free(message);
//    free(hash);
//    assert(findHashEx(290, &message, &hash, "sha256") == 0);
//    assert(findHashEx(10, &message, &hash, "sha256") == 1);
//    assert(message && hash && checkHash(10, hash));
//    free(message);
//    free(hash);
//    assert(findHash(-1, &message, &hash) == 0);
    return EXIT_SUCCESS;
}
#endif /* __PROGTEST__ */