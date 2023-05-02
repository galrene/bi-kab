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
    const char * m_PemFile;
    const char * m_Cipher;
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
public:
    CHybridCipher ()
    : m_Ctx ( NULL ), m_Cipher ( NULL ), m_Cfg (),
      m_EncKey ( NULL ), m_EncKeyLen ( 0 ), m_PKey ( NULL ) {}
    explicit CHybridCipher ( const TCryptoConfig & cfg )
    : m_Ctx ( NULL ), m_Cipher ( NULL ), m_Cfg ( cfg ),
      m_EncKey ( NULL ), m_EncKeyLen ( 0 ), m_PKey ( NULL ) {}

    ~CHybridCipher();

    bool updateFile ( ifstream & inFile, ofstream & outFile );

    bool init ( bool seal );

    bool writeHeader ( ofstream & outFile );

    bool readCfg ( ifstream &inFile, const char *privateKeyFile );

    bool fReadKey(const char *fileName, bool seal);
};

CHybridCipher::~CHybridCipher() {
    if ( m_PKey )
        EVP_PKEY_free ( m_PKey );
    if ( m_Ctx )
        EVP_CIPHER_CTX_free ( m_Ctx );
    if ( m_EncKey )
        free (m_EncKey );
}

bool CHybridCipher::updateFile ( ifstream & inFile, ofstream & outFile ) {
    char inBuff[INBUFF_CAP] = {};
    char outBuff[OUTBUFF_CAP] = {};
    int outSize = 0;
    while ( inFile.good() && outFile.good() ) {
        inFile.read ( inBuff, INBUFF_CAP );
        if ( ! EVP_SealUpdate (m_Ctx,
                                 reinterpret_cast<unsigned char *>(outBuff), &outSize,
                                 reinterpret_cast<const unsigned char *>(inBuff), inFile.gcount() ) )
            return false;
        outFile.write ( outBuff, outSize );
    }
    // finished reading infile
    if ( inFile.eof() ) {
        if ( ! EVP_SealFinal ( m_Ctx, reinterpret_cast<unsigned char *>(outBuff), &outSize ) )
            return false;
        outFile.write ( outBuff, outSize );
        if ( ! outFile.good() )
            return false;
        return true;
    }
    return false;
}

bool CHybridCipher::fReadKey ( const char * fileName, bool publicKey ) {
    if ( ! fileName )
        return false;
    FILE * pemFile = fopen ( fileName, "r" );
    if ( ! pemFile )
        return false;
    if ( publicKey )
        m_PKey = PEM_read_PUBKEY ( pemFile, NULL, NULL, NULL  );
    else
        m_PKey = PEM_read_PrivateKey ( pemFile, NULL, NULL, NULL );
    fclose ( pemFile );
    if ( ! m_PKey )
        return false;
    return true;
}

bool CHybridCipher::init ( bool seal ) {
    OpenSSL_add_all_ciphers();
    if ( ! m_Cfg.m_PemFile || ! m_Cfg.m_Cipher  )
        return false;
    if ( m_Ctx = EVP_CIPHER_CTX_new(); ! m_Ctx )
        return false;
    if ( m_Cipher = EVP_get_cipherbyname ( m_Cfg.m_Cipher ); ! m_Cipher )
        return false;
    if ( ! fReadKey ( m_Cfg.m_PemFile, seal ) )
        return false;
    if ( seal ) {
        m_EncKey = ( unsigned char * ) malloc ( EVP_PKEY_size(m_PKey) );
        if ( ! EVP_SealInit ( m_Ctx, m_Cipher,
                              &m_EncKey, &m_EncKeyLen , m_IV,
                              &m_PKey, 1 ) )
            return false;
    }
    else {
        if ( ! EVP_OpenInit ( m_Ctx, m_Cipher,
                              m_EncKey, m_EncKeyLen , m_IV,
                              m_PKey ) )
            return false;
    }
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
bool CHybridCipher::writeHeader ( ofstream & outFile ) {
    if ( ! outFile.good() )
        return false;
    stringstream ss;

    ss << EVP_CIPHER_nid ( m_Cipher );
    outFile.write ( ss.str().c_str(), ss.str().size() ); // write NID
    ss.clear();

    ss << m_EncKeyLen;
    outFile.write ( ss.str().c_str(), ss.str().size() ); // write EKlen
    ss.clear();

    ss << m_EncKey;
    outFile.write ( ss.str().c_str(), ss.str().size() ); // write EK
    ss.clear();

    ss << m_IV;
    outFile.write ( ss.str().c_str(), ss.str().size() ); // write IV
    ss.clear();

    if ( ! outFile.good() )
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
bool CHybridCipher::readCfg ( ifstream & inFile, const char * privateKeyFile ) {
    if ( ! inFile.good() || ! privateKeyFile )
        return false;

    char NID[5] = {};
    inFile.read ( NID, 4 );
    if ( inFile.gcount() != 4 )
        return false;
    char EKlen[5] = {};
    inFile.read ( EKlen, 4 );
    if ( inFile.gcount() != 4 )
        return false;

    int nid = 0;
    if ( nid = stoi ( NID ); ! nid )
        return false;
    if ( m_Cipher =  EVP_get_cipherbynid ( nid ); ! m_Cipher )
        return false;

    int ekLen = 0;
    if ( ekLen = stoi ( EKlen ); ! ekLen )
        return false;

    char * EK = new char[ekLen];

    return true;
}

bool seal ( const char * inFile, const char * outFile, const char * publicKeyFile, const char * symmetricCipher ) {
    CHybridCipher c ( { publicKeyFile, symmetricCipher } );
    ifstream ifs ( inFile ); ofstream ofs ( outFile );
    if ( ! ifs.good() || ! ofs.good() )
        return false;
    if ( ! c.init ( true ) || ! c.writeHeader ( ofs ) || ! c.updateFile ( ifs, ofs ) ) {
        std::remove ( outFile );
        return false;
    }
    return true;
}

bool open ( const char * inFile, const char * outFile, const char * privateKeyFile ) {
    ifstream ifs ( inFile ); ofstream ofs ( outFile );
    if ( ! ifs.good() || ! ofs.good() )
        return false;
    CHybridCipher c;
    if ( ! c.readCfg ( ifs, privateKeyFile ) ||
         ! c.init ( false ) || ! c.updateFile ( ifs, ofs ) )
        return false;
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

