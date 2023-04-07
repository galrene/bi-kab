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
    ~CHasher() {
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
    unsigned int    getHashLen() { return m_HashLength; }

    /**
     * Feed text to hashing function.
     * @param text
     * @param size length of text excluding \0
     * @return true success, false failure
     */
    bool feed ( char * text, size_t size );
};

bool CHasher::feed ( char * text, size_t size ) {
    // feed message to function
    if ( ! EVP_DigestUpdate ( m_Ctx, text, size ) ) {
//        printf("Failed to feed the message.\n");
        return false;
    }
    return true;
}

unsigned char * CHasher::final () {
    // get the hash
    if ( ! EVP_DigestFinal_ex ( m_Ctx, m_Hash, &m_HashLength ) ) {
//        printf("Failed to finalize the hash.\n");
        return NULL;
    }
    return m_Hash;
}

bool CHasher::init () {
    if ( m_Ctx = EVP_MD_CTX_new(); m_Ctx == NULL ) {
//        printf("Context creation/initialisation failed.\n");
        return false;
    }
    if ( ! EVP_DigestInit_ex( m_Ctx, m_HashFuncType, NULL ) ) {
//        printf( "Context setup for sha512 failed.\n");
        return false;
    }
    m_Hash = ( unsigned char * ) calloc ( m_MaxHashSize, sizeof ( unsigned char ) );
    if ( ! m_Hash ) {
//        printf( "Hash allocation failed.\n");
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
 *
 * @param bits requested length of 0 prefix
 * @param message output found message
 * @param hash hash of message starting with bits amount of 0's
 * Initialise with a text and then use it's hash to quickly generate a new hash until finding one
 * with n 0 bits.
 * @return 1 if success, 0 if failure or wrong parameters
 */
int findHash ( int bits, char ** message, char ** hash ) {
    if ( bits < 0 || bits > 512 || *message == NULL || *hash == NULL )
        return 0;
    CHasher hf ( HASH_SIZE );
    if ( ! hf.init() )
        return 0;

    std::string initialMessage = "raz si dole hore, v pozore, vo svojom dvore, obzore, v nore, na";
    char *msg = ( char * ) calloc ( HASH_SIZE, sizeof(char) ); // HASH_SIZE, because we'll use the hash as the next generated message
    memcpy ( msg, initialMessage.c_str(), HASH_SIZE );

    while ( true ) {
        if (!hf.feed(msg, HASH_SIZE) || !hf.final()) {
            free(msg);
            return 0;
        }
        if ( foundMessage ( bits, hf.getHash(), hf.getHashLen() ) )
            break;
        memcpy ( msg, hf.getHash(), HASH_SIZE );
    }
//    printf( "Hladany pocet nul: %d\n", bits );
//    printf("Hash textu \"%s\" je: ", msg);
//    for (unsigned int i = 0; i < hf.getHashLen(); i++)
//        printf("%02x", hf.getHash()[i]);

    std::string hexMsg = convertToHex(msg, HASH_SIZE);
    msg = ( char * ) realloc ( msg, hexMsg.size() + 1 );
    if ( ! msg ) {
        free(msg);
        return 0;
    }
    strncpy ( msg, hexMsg.c_str(), hexMsg.size() + 1 );
    *message = msg;


    std::string hexHash = convertToHex(reinterpret_cast<const char *>(hf.getHash()), hf.getHashLen());
    *hash = ( char * ) malloc ( hexHash.size() + 1 );
    if ( ! *hash ) {
        free(msg);
        free(*hash);
        return 0;
    }
    strncpy ( *hash, hexHash.c_str(), hexHash.size() + 1 );
//    std::cout << "\nMy msg: " << msg << "\nMy hash: " << *hash << std::endl;
//    printf("\n======================================\n");
    return 1;
}


int findHashEx (int bits, char ** message, char ** hash, const char * hashFunction) {
    /* TODO or use dummy implementation */
    return 1;
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
    assert(findHash(4, &message, &hash) == 1);
    assert(message && hash && checkHash(4, hash));
    free(message);
    free(hash);
    assert(findHash(16, &message, &hash) == 1);
    assert(message && hash && checkHash(16, hash));
    free(message);
    free(hash);
    assert(findHash(-1, &message, &hash) == 0);
    return EXIT_SUCCESS;
}
#endif /* __PROGTEST__ */