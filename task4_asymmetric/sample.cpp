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
    unsigned char * m_EncKey; // encrypted symmetric cipher key
    int m_EncKeyLen;
    EVP_PKEY * m_PKey; // public or private key
public:
    CHybridCipher ()
    : m_Ctx ( NULL ), m_Cipher ( NULL ), m_Cfg (),
      m_EncKey ( NULL ), m_EncKeyLen ( 0 ), m_PKey ( NULL ) {
        OpenSSL_add_all_ciphers();
    }
    explicit CHybridCipher ( const TCryptoConfig & cfg )
    : m_Ctx ( NULL ), m_Cipher ( NULL ), m_Cfg ( cfg ),
      m_EncKey ( NULL ), m_EncKeyLen ( 0 ), m_PKey ( NULL ) {}

    ~CHybridCipher();

    bool updateFile ( ifstream & inFile, ofstream & outFile );

    bool init ( bool seal );

    bool writeHeader ( ofstream & outFile );

    bool fReadCfg ( ifstream &inFile, const char *privateKeyFile );

    bool fReadKey ( const char *fileName, bool publicKey );
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
        if ( ! EVP_CipherUpdate ( m_Ctx,
                                 reinterpret_cast<unsigned char *>(outBuff), &outSize,
                                 reinterpret_cast<const unsigned char *>(inBuff), inFile.gcount() ) )
            return false;
        outFile.write ( outBuff, outSize );
    }
    // finished reading infile
    if ( inFile.eof() ) {
        if ( ! EVP_CipherFinal ( m_Ctx, reinterpret_cast<unsigned char *>(outBuff), &outSize ) )
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
    int nid = EVP_CIPHER_nid ( m_Cipher );
    outFile.write ( (char*)&nid, sizeof(int) );
    outFile.write ( (char*)&m_EncKeyLen, sizeof(int) );
    outFile.write ( (char*)m_EncKey, m_EncKeyLen );
    outFile.write ( (char*)m_IV, EVP_CIPHER_iv_length(m_Cipher) );
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
bool CHybridCipher::fReadCfg ( ifstream & inFile, const char * privateKeyFile ) {
    if ( ! inFile.good() || ! privateKeyFile )
        return false;
    m_Cfg.m_PemFile = privateKeyFile;

    int nid = 0;
    inFile.read ( (char*)&nid, 4 );
    if ( inFile.gcount() != 4 || nid == 0 )
        return false;

    m_EncKeyLen = 0;
    inFile.read ( (char*)&m_EncKeyLen, 4 );
    if ( inFile.gcount() != 4 || m_EncKeyLen == 0 )
        return false;

    if ( m_Cipher = EVP_get_cipherbynid ( nid ); ! m_Cipher )
        return false;
    m_Cfg.m_Cipher = EVP_CIPHER_name (m_Cipher);

    m_EncKey = ( unsigned char * ) malloc ( m_EncKeyLen );
    inFile.read (reinterpret_cast<char *>(m_EncKey), m_EncKeyLen );
    if ( inFile.gcount() != m_EncKeyLen )
        return false;

    if ( int ivLen = EVP_CIPHER_iv_length ( m_Cipher ); ivLen != 0 ) {
        inFile.read (reinterpret_cast<char *>(m_IV), ivLen );
        if ( inFile.gcount() != ivLen )
            return false;
    }
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
    if ( ! c.fReadCfg ( ifs, privateKeyFile ) ||
         ! c.init ( false ) || ! c.updateFile ( ifs, ofs ) )
        return false;
    return true;
}

#ifndef __PROGTEST__

int main ( void ) {
    assert( seal("fileToEncrypt", "sealed.bin", "PublicKey.pem", "aes-128-cbc") );
    assert( open("sealed.bin", "openedFileToEncrypt", "PrivateKey.pem") );

    assert( open("sealed_sample.bin", "opened_sample.txt", "PrivateKey.pem") );

    return 0;
}

#endif /* __PROGTEST__ */

