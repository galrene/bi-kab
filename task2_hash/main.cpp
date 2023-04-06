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

class CHashFinder {
private:
    const EVP_MD * m_HashFuncType;
    EVP_MD_CTX * m_Ctx;

    unsigned char * m_Hash;
    unsigned int m_HashLength;
public:
    CHashFinder ()
    : m_HashFuncType ( EVP_sha256() ), m_Ctx ( NULL ), m_Hash ( NULL), m_HashLength ( 0 ) {}
    ~CHashFinder() {
        free();
    }
    /**
    * Create and initialise context, initialise sha256 hashing function,
    * allocate memory for hash.
    * @return 1 success, 0 fail
    */
    bool init ();
    /**
     * Calculate the hash from fed message.
     * @return hash on sucess, NULL on failure
     */
    unsigned char * final();
    /**
     * Get the stored hash calculated by final().
     * @return hash on success, NULL when no hash calculated yet
     */
    unsigned char * getHash() { return m_Hash; }
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
    int free();
};

bool CHashFinder::feed ( char * text, size_t size ) {
    // feed message to function
    if ( ! EVP_DigestUpdate ( m_Ctx, text, size ) )
        return false;
    return true;
}

unsigned char * CHashFinder::final () {
    // get the hash
    if ( ! EVP_DigestFinal_ex ( m_Ctx, m_Hash, &m_HashLength ) )
        return NULL;
    return m_Hash;
}

bool CHashFinder::init () {
    if ( m_Ctx = EVP_MD_CTX_new(); m_Ctx == NULL ) {
        printf("Context creation/initialisation failed.\n");
        free();
        return false;
    }
    if ( ! EVP_DigestInit_ex( m_Ctx, m_HashFuncType, NULL ) ) {
        printf( "Context setup for sha256 failed.\n");
        free();
        return false;
    }
    m_Hash = ( unsigned char * ) malloc ( EVP_MAX_MD_SIZE );
    if ( ! m_Hash ) {
        printf( "Hash allocation failed.\n");
        free();
        return false;
    }

    return true;
}

int CHashFinder::free () {
    if ( m_Ctx )
        EVP_MD_CTX_free ( m_Ctx );
    if ( m_Hash )
        OPENSSL_free ( m_Hash );
    return 1;
}

/**
 * 32-bit LFSR
 */
class LFSR {
private:
    uint32_t m_State;
public:
    LFSR ( uint32_t  seed ) : m_State ( seed ) {}
    uint32_t  next();
};

uint32_t LFSR::next () {
    uint32_t bit = m_State & 1;
    m_State >>= 1;
    if (bit == 1)
        m_State ^= 0x80000057; // XOR with a tap sequence
    return m_State;
}
/**
 * Generates a pseudorandom 64 byte string without null-termination.
 * @return
 */
char * getRandom64B () {
    for ( int i = 0; i < 16; i++ )

}

bool foundMessage ( unsigned char * hash, size_t hashSize ) {

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
    CHashFinder hf;
    if ( ! hf.init() )
        return 0;

    char * inputString = NULL;
    while ( ! foundMessage ( hf.getHash() ) ) {
        uint32_t mess = lfsr.next();
        inputString = getRandom64B();
        if ( ! hf.feed ( iStringnput, sizeof(inputString) ) )
            return 0;
        if ( ! hf.final() )
            return 0;
    }


    return 1;
}


int findHashEx (int bits, char ** message, char ** hash, const char * hashFunction) {
    /* TODO or use dummy implementation */
    return 1;
}

#ifndef __PROGTEST__

int checkHash(int bits, char * hexString) {
    // DIY
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

