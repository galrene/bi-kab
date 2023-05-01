#ifndef __PROGTEST__
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

using namespace std;

#endif /* __PROGTEST__ */

struct TCryptoConfig {
    const char * m_InFile;
    const char * m_Outfile;
    const char * m_PublicKeyFile;
    const char * m_Cipher;
    TCryptoConfig ( const char * inf, const char * outf, const char * pkf, const char * cipher )
            : m_Cipher ( cipher ), m_InFile ( inf ), m_Outfile ( outf ), m_PublicKeyFile ( pkf )
    {}
};

class CHybridCipher {
private:
    EVP_CIPHER_CTX * m_Ctx;
    const EVP_CIPHER * m_Cipher;
    TCryptoConfig m_Cfg;
    unsigned char m_IV[EVP_MAX_IV_LENGTH] = {};
    unsigned char * m_EncKey;
    int m_EncKeyCnt;

    EVP_PKEY * m_PKey;
    ifstream m_Infile;
    ifstream m_Outfile;
public:
    explicit CHybridCipher ( const TCryptoConfig & cfg )
    : m_Ctx ( NULL ), m_Cipher ( NULL ), m_Cfg ( cfg ),
      m_EncKey ( NULL ), m_EncKeyCnt ( 0 ), m_PKey ( NULL ) {}

    ~CHybridCipher();

    bool init ( bool encrypt );
};

CHybridCipher::~CHybridCipher() {
    if ( m_Outfile.is_open() )
        std::remove ( m_Cfg.m_Outfile );
    if ( m_PKey )
        EVP_PKEY_free ( m_PKey );
}

bool CHybridCipher::init ( bool encrypt ) {
    OpenSSL_add_all_ciphers();
    if ( ! m_Cfg.m_InFile || ! m_Cfg.m_Outfile || ! m_Cfg.m_PublicKeyFile || ! m_Cfg.m_Cipher )
        return false;
    if ( m_Ctx = EVP_CIPHER_CTX_new(); ! m_Ctx )
        return false;
    if ( m_Cipher = EVP_get_cipherbyname ( m_Cfg.m_Cipher ); ! m_Cipher )
        return false;
    m_Infile.open ( m_Cfg.m_InFile ); m_Outfile.open ( m_Cfg.m_Outfile );
    if ( ! m_Infile.good() || ! m_Outfile.good() )
        return false;
    FILE * pkFile = fopen ( m_Cfg.m_PublicKeyFile, "r" );
    if ( ! pkFile ) {
        fclose ( pkFile );
        return false;
    }
    m_PKey = PEM_read_PUBKEY ( pkFile, NULL, NULL, NULL  );
    fclose ( pkFile );
    if ( ! m_PKey )
        return false;

    if ( ! EVP_SealInit ( m_Ctx, m_Cipher,
                          &m_EncKey, &m_EncKeyCnt , m_IV,
                          &m_PKey, EVP_PKEY_size ( m_PKey ) ) )
        return false;
    return true;
}

bool seal ( const char * inFile, const char * outFile, const char * publicKeyFile, const char * symmetricCipher ) {
    CHybridCipher cipher ( { inFile, outFile, publicKeyFile, symmetricCipher } );
    if ( ! cipher.init ( true ) )
        return false;
    return true;
}


bool open ( const char * inFile, const char * outFile, const char * privateKeyFile ) {
    //waiting for code...
    return true;
}



#ifndef __PROGTEST__

int main ( void )
{
    assert( seal("fileToEncrypt", "sealed.bin", "PublicKey.pem", "aes-128-cbc") );
    assert( open("sealed.bin", "openedFileToEncrypt", "PrivateKey.pem") );

    assert( open("sealed_sample.bin", "opened_sample.txt", "PrivateKey.pem") );

    return 0;
}

#endif /* __PROGTEST__ */

