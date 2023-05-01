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

#define INBUFF_CAP 1024
#define OUTBUFF_CAP ( INBUFF_CAP + EVP_MAX_BLOCK_LENGTH )

struct TCryptoConfig {
    const char * m_InFile;
    const char * m_Outfile;
    const char * m_PemFile;
    const char * m_Cipher;
    TCryptoConfig ( const char * inf, const char * outf, const char * pkf, const char * cipher )
            : m_Cipher ( cipher ), m_InFile ( inf ), m_Outfile ( outf ), m_PemFile ( pkf )
    {}
};

class CHybridCipher {
private:
    EVP_CIPHER_CTX * m_Ctx;
    const EVP_CIPHER * m_Cipher;
    TCryptoConfig m_Cfg;
    unsigned char m_IV[EVP_MAX_IV_LENGTH] = {};
    unsigned char * m_EncKey;
    int m_EncKeyLen;

    EVP_PKEY * m_PKey;
    ifstream m_Infile;
    ofstream m_Outfile;
public:
    explicit CHybridCipher ( const TCryptoConfig & cfg )
    : m_Ctx ( NULL ), m_Cipher ( NULL ), m_Cfg ( cfg ),
      m_EncKey ( NULL ), m_EncKeyLen ( 0 ), m_PKey ( NULL ) {}

    ~CHybridCipher();

    bool updateFile ();

    bool init ();

    bool writeHeader();
};

CHybridCipher::~CHybridCipher() {
    if ( m_PKey )
        EVP_PKEY_free ( m_PKey );
    if ( m_Ctx )
        EVP_CIPHER_CTX_free ( m_Ctx );
}

bool CHybridCipher::updateFile () {
    char inBuff[INBUFF_CAP] = {};
    char outBuff[OUTBUFF_CAP] = {};
    int outSize = 0;
    while ( m_Infile.good() && m_Outfile.good() ) {
        m_Infile.read ( inBuff, INBUFF_CAP );
        if ( ! EVP_SealUpdate (m_Ctx,
                                 reinterpret_cast<unsigned char *>(outBuff), &outSize,
                                 reinterpret_cast<const unsigned char *>(inBuff), m_Infile.gcount() ) )
            return false;
        m_Outfile.write ( outBuff, outSize );
    }
    // finished reading infile
    if ( m_Infile.eof() ) {
        if ( ! EVP_SealFinal ( m_Ctx, reinterpret_cast<unsigned char *>(outBuff), &outSize ) )
            return false;
        m_Outfile.write ( outBuff, outSize );
        if ( ! m_Outfile.good() )
            return false;
        return true;
    }
    return false;
}

bool CHybridCipher::init () {
    OpenSSL_add_all_ciphers();
    if ( ! m_Cfg.m_InFile || ! m_Cfg.m_Outfile || ! m_Cfg.m_PemFile || ! m_Cfg.m_Cipher )
        return false;
    if ( m_Ctx = EVP_CIPHER_CTX_new(); ! m_Ctx )
        return false;
    if ( m_Cipher = EVP_get_cipherbyname ( m_Cfg.m_Cipher ); ! m_Cipher )
        return false;
    m_Infile.open ( m_Cfg.m_InFile ); m_Outfile.open ( m_Cfg.m_Outfile );
    if ( ! m_Infile.good() || ! m_Outfile.good() )
        return false;
    FILE * pkFile = fopen ( m_Cfg.m_PemFile, "r" );
    if ( ! pkFile ) {
        fclose ( pkFile );
        return false;
    }
    m_PKey = PEM_read_PUBKEY ( pkFile, NULL, NULL, NULL  );
    fclose ( pkFile );
    if ( ! m_PKey )
        return false;
    // TODO: m_EncKey probably wrong
    if ( ! EVP_SealInit ( m_Ctx, m_Cipher,
                          &m_EncKey, &m_EncKeyLen , m_IV,
                          &m_PKey, EVP_PKEY_size ( m_PKey ) ) )
        return false;
    return true;
}
/**
    Pozice v souboru 	Délka 	    Struktura 	        Popis
    0 	                4 B 	    int 	            NID - numerical identifier for an OpenSSL cipher. (Použitá symetrická šifra)
    4 	                4 B 	    int 	            EKlen - délka zašifrovaného klíče
    8 	                EKlen B 	pole unsigned char 	Zašifrovaný klíč pomocí RSA
    8 + EKlen 	        IVlen B 	pole unsigned char 	Inicializační vektor (pokud je potřeba)
    8 + EKlen + IVlen 	  —    	    pole unsigned char 	Zašifrovaná data
 */
bool CHybridCipher::writeHeader() {
    if ( ! m_Outfile.good() )
        return false;
    stringstream ss;

    ss << EVP_CIPHER_nid ( m_Cipher );
    m_Outfile.write ( ss.str().c_str(), ss.str().size() ); // write NID
    ss.clear();

    ss << m_EncKeyLen;
    m_Outfile.write ( ss.str().c_str(), ss.str().size() ); // write EKlen
    ss.clear();

    ss << m_EncKey;
    m_Outfile.write ( ss.str().c_str(), ss.str().size() ); // write EK
    ss.clear();

    ss << m_IV;
    m_Outfile.write ( ss.str().c_str(), ss.str().size() ); // write IV
    ss.clear();

    if ( ! m_Outfile.good() )
        return false;
    return true;
}

bool seal ( const char * inFile, const char * outFile, const char * publicKeyFile, const char * symmetricCipher ) {
    CHybridCipher c ( { inFile, outFile, publicKeyFile, symmetricCipher } );
    if ( ! c.init () || ! c.writeHeader() || ! c.updateFile() ) {
        std::remove ( outFile ); // TODO: won't break things in destructors?
        return false;
    }
    return true;
}

bool open ( const char * inFile, const char * outFile, const char * privateKeyFile ) {
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

