#pragma clang diagnostic push
#pragma ide diagnostic ignored "modernize-use-auto"
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

#define MAX_HASH_SIZE EVP_MAX_MD_SIZE

class CHashFinder {
private:
    const EVP_MD * m_HashFuncType;
    EVP_MD_CTX * m_Ctx;

    unsigned char * m_Hash;
    unsigned int m_HashLength;
    int m_MaxHashSize;
public:
    explicit CHashFinder ( int hashSize )
    : m_HashFuncType ( EVP_sha512() ), m_Ctx ( NULL ), m_Hash ( NULL ), m_HashLength ( 0 ), m_MaxHashSize ( hashSize ) {}
    ~CHashFinder() {
        if ( m_Ctx )
            EVP_MD_CTX_free ( m_Ctx );
        if ( m_Hash )
            free ( m_Hash );
    }
    /**
    * Create and initialise context, initialise sha512 hashing function,
    * allocate memory for hash.
    * @return 1 success, 0 fail
    */
    bool init ();
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
    bool feed ( char * text, size_t size );
    /**
     * Frees all allocated resources.
     * @return 1 success, 0 fail
     */
//    int free();
};

bool CHashFinder::feed ( char * text, size_t size ) {
    // feed message to function
    if ( ! EVP_DigestUpdate ( m_Ctx, text, size ) ) {
        printf("Failed to feed the message.\n");
        return false;
    }
    return true;
}

unsigned char * CHashFinder::final () {
    // get the hash
    if ( ! EVP_DigestFinal_ex ( m_Ctx, m_Hash, &m_HashLength ) ) {
        printf("Failed to finalize the hash.\n");
        return NULL;
    }
    return m_Hash;
}

bool CHashFinder::init () {
    if ( m_Ctx = EVP_MD_CTX_new(); m_Ctx == NULL ) {
        printf("Context creation/initialisation failed.\n");
        return false;
    }
    if ( ! EVP_DigestInit_ex( m_Ctx, m_HashFuncType, NULL ) ) {
        printf( "Context setup for sha512 failed.\n");
        return false;
    }
    m_Hash = ( unsigned char * ) calloc ( m_MaxHashSize, sizeof ( unsigned char ) );
    if ( ! m_Hash ) {
        printf( "Hash allocation failed.\n");
        return false;
    }

    return true;
}

bool foundMessage ( const int bits, const unsigned char * hash, const size_t hashLength ) {
    if ( ! hash || hashLength <= 0 || bits < 0  )
        return false;
    if ( bits == 0 )
        return hash[0] & 0b10000000;

    int zeroBitCounter = 0;
    for ( size_t i = 0; i < hashLength; i++ ) {
        unsigned char byte = hash[i];
        for ( int j = 0; j < 8; j++ ) {
            if ( ( byte & 0b10000000 ) == 0 )
                zeroBitCounter++;
            byte <<= 1;
        }
        if ( zeroBitCounter >= bits )
            return true;
    }
    return false;
}

/**
 *
 * @param bits requested length of 0 prefix
 * @param message output found message
 * @param hash hash of message starting with bits amount of 0's
 * @return 1 if success, 0 if failure or wrong parameters
 */
int findHash (int bits, char ** message, char ** hash) {
    if ( bits < 0 || *message == NULL || *hash == NULL )
        return 0;
    CHashFinder hf ( MAX_HASH_SIZE );
    if ( ! hf.init() )
        return 0;

    std::string initialMessage = "raz si dole hore, v pozore, vo svojom dvore, obzore, v nore, nav";
    char * msg = ( char * ) calloc ( initialMessage.size(), sizeof ( char ) );
    memcpy ( msg, initialMessage.c_str(), initialMessage.size() );

    while ( true ) {
        if ( ! hf.feed ( msg, initialMessage.size() ) || ! hf.final() ) {
            free ( msg );
            return 0;
        }
        if ( foundMessage ( bits, hf.getHash(), hf.getHashLen() ) )
            break;
        memcpy ( msg, hf.getHash() , initialMessage.size() );
    }

    *message = msg;
    *hash = ( char * ) calloc ( MAX_HASH_SIZE, sizeof ( char ) );
    memcpy ( *hash, ( char * ) hf.getHash(), hf.getHashLen() );
    return 1;
}


int findHashEx (int bits, char ** message, char ** hash, const char * hashFunction) {
    /* TODO or use dummy implementation */
    return 1;
}

#ifndef __PROGTEST__

int checkHash ( int bits, char * hexString ) {
    if ( bits == 0 )
        return hexString[0] & 0b10000000;
    int zeroBitCounter = 0;
    for ( size_t i = 0; i < 64; i++ ) {
        unsigned char byte = hexString[i];
        for ( int j = 0; j < 8; j++ ) {
            if ( ( byte & 0b10000000 ) == 0 )
                zeroBitCounter++;
            byte <<= 1;
        }
        if ( zeroBitCounter >= bits )
            return true;
    }

}

int main (void) {
    char * message, * hash;
    assert(findHash(0, &message, &hash) == 1);
    assert(message && hash && checkHash(0, hash));
    free(message);
    free(hash);
    assert(findHash(1, &message, &hash) == 1);
    assert(message && hash && checkHash(1, hash));
    free(message);
    free(hash);
    assert(findHash(2, &message, &hash) == 1);
    assert(message && hash && checkHash(2, hash));
    free(message);
    free(hash);
    assert(findHash(3, &message, &hash) == 1);
    assert(message && hash && checkHash(3, hash));
    free(message);
    free(hash);
    assert(findHash(-1, &message, &hash) == 0);
    return EXIT_SUCCESS;
}
#endif /* __PROGTEST__ */


#pragma clang diagnostic pop