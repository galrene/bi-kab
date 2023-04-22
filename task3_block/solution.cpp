#ifndef __PROGTEST__
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <unistd.h>
#include <string>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

struct crypto_config
{
	const char * m_crypto_function;
	std::unique_ptr<uint8_t[]> m_key;
	std::unique_ptr<uint8_t[]> m_IV;
	size_t m_key_len;
	size_t m_IV_len;
};

#endif /* __PROGTEST__ */

#define INBUFF_CAP 1024
#define OUTBUFF_CAP INBUFF_CAP

class CCipher {
private:
    EVP_CIPHER_CTX * m_Ctx;
    const EVP_CIPHER * m_Cipher;
    struct crypto_config & m_Cfg;
    bool validateConfig ( bool encrypt );
public:
    CCipher ( struct crypto_config & cfg )
    : m_Ctx ( NULL ), m_Cipher ( NULL ), m_Cfg ( cfg ) {}
    ~CCipher () {
        EVP_CIPHER_CTX_free(m_Ctx);
    }
    /**
     * Validate supplied config, initialise context and given cipher.
     * @encrypt true == encrypt mode, false == decrypt mode
     */
    bool init ( bool encrypt );
    bool updateFile ( ifstream & ifs, ofstream & ofs );
};

bool CCipher::validateConfig ( bool encrypt ) {
    size_t cipherKeyLen = EVP_CIPHER_key_length ( m_Cipher );
    size_t cipherIVLen = EVP_CIPHER_iv_length ( m_Cipher );
    if ( m_Cfg.m_key == nullptr
        || m_Cfg.m_key_len < cipherKeyLen ) {
        if ( ! encrypt ) {
            cout << "Key error" << endl;
            return false;
        }
        m_Cfg.m_key = make_unique<uint8_t[]> ( cipherKeyLen );
        m_Cfg.m_key_len = cipherKeyLen;
        RAND_bytes ( m_Cfg.m_key.get(), cipherKeyLen );
    }
    if ( m_Cfg.m_IV == nullptr || m_Cfg.m_IV_len < cipherIVLen ) {
        if ( cipherIVLen ) {
            if ( ! encrypt ) {
                cout << "IV error" << endl;
                return false;
            }
            m_Cfg.m_IV = make_unique<uint8_t[]> ( cipherIVLen );
            m_Cfg.m_IV_len = cipherIVLen;
            RAND_bytes ( m_Cfg.m_IV.get(), cipherIVLen );
        }
    }
    return true;
}

/**
 * The functions EVP_EncryptInit(), EVP_EncryptInit_ex(), EVP_EncryptFinal(), EVP_DecryptInit(), EVP_DecryptInit_ex(),
 * EVP_CipherInit(), EVP_CipherInit_ex() and EVP_CipherFinal() are obsolete but are retained for compatibility with
 * existing code. New code should use EVP_EncryptInit_ex2(), EVP_EncryptFinal_ex(), EVP_DecryptInit_ex2(),
 * EVP_DecryptFinal_ex(), EVP_CipherInit_ex2() and EVP_CipherFinal_ex() because they can reuse an existing context
 * without allocating and freeing it up on each call.
 */

bool CCipher::updateFile ( ifstream & ifs, ofstream & ofs ) {
    char inBuff[INBUFF_CAP] = {};
    char outBuff[OUTBUFF_CAP] = {};
    int outSize = 0;
    while ( ifs.good() && ofs.good() ) {
        ifs.read ( inBuff, INBUFF_CAP );
        if ( ! EVP_CipherUpdate (m_Ctx,
        reinterpret_cast<unsigned char *>(outBuff), &outSize,
        reinterpret_cast<const unsigned char *>(inBuff), INBUFF_CAP ) ) {
            cout << "Update failed" << endl;
            return false;
        }
        ofs.write ( outBuff, outSize );
    }
    // finished reading infile
    if ( ifs.eof() ) {
        if ( ! EVP_CipherFinal_ex ( m_Ctx, reinterpret_cast<unsigned char *>(outBuff), &outSize ) ) {
            cout << "Final failed" << endl;
            return false;
        }
        ofs.write ( outBuff, outSize );
        if ( ! ofs.good() ) {
            cout << "Final write failed" << endl;
            return false;
        }
        return true;
    }
    return false;
}

bool CCipher::init ( bool encrypt ) {
    if ( m_Ctx = EVP_CIPHER_CTX_new(); ! m_Ctx ) {
        cout << "Context creation" << endl;
        return false;
    }
    OpenSSL_add_all_ciphers();
    if ( m_Cipher = EVP_get_cipherbyname (m_Cfg.m_crypto_function ); ! m_Cipher ) {
        cout << "Cipher name not found" << endl;
        return false;
    }
    if ( ! validateConfig ( encrypt ) ) {
        cout << "Cfg validation failed" << endl;
        return false;
    }
    if ( ! EVP_CipherInit_ex2( m_Ctx, m_Cipher, m_Cfg.m_key.get(), m_Cfg.m_IV.get(), static_cast<int> ( encrypt ), NULL ) ) {
        cout << "Init failed" << endl;
        return false;
    }
    return true;
}

bool copyHeader ( ifstream & ifs, ofstream & ofs ) {
    char header[18] = {0};
    ifs.read ( header, 18 );
    if ( ifs.gcount() != 18 ) {
        cout << "Unable to read header" << endl;
        return false;
    }
    ofs.write ( header, 18 );
    if ( ! ofs.good() )
        return false;
    return true;
}

bool crypt_ex ( const std::string & in_filename, const std::string & out_filename, crypto_config & config, bool encrpyt ) {
    CCipher c ( config );
    ifstream ifs ( in_filename );
    ofstream ofs; ofs.open ( out_filename );
    if ( ! ifs.good() || ! ofs.good() ) {
        cout << "Unable to open file" << endl;
        return false;
    }
    if ( ! copyHeader ( ifs, ofs ) ) {
        cout << "Unable to copy header" << endl;
        return false;
    }
    if ( ! c.init ( encrpyt ) || ! c.updateFile ( ifs, ofs ) ) {
        cout << "Cipher failed" << endl;
        return false;
    }
    // close ifs, ofs?
    return true;
}

bool encrypt_data ( const std::string & in_filename, const std::string & out_filename, crypto_config & config ) {
    return crypt_ex(in_filename, out_filename, config, true );
}

bool decrypt_data ( const std::string & in_filename, const std::string & out_filename, crypto_config & config ) {
    return crypt_ex(in_filename, out_filename, config, false );
}


#ifndef __PROGTEST__
#include <filesystem>
// TODO: test for files with different lengths!
bool compare_files ( const char * name1, const char * name2 ) {
    namespace fs = std::filesystem;
    if ( fs::file_size(name1) != fs::file_size(name2) ) {
        cout << "File size mismatch" << endl;
        return false;
    }
    ifstream ifs1 (name1);
    ifstream ifs2 (name2);
    string word;
    string word2;
    while ( ifs1 >> word && ifs2 >> word2 ) {
        if ( word != word2 ) {
            cout << "Files not equal" << endl;
            return false;
        }
    }
    return true;
}

int main ( void )
{
	crypto_config config {nullptr, nullptr, nullptr, 0, 0};

	// ECB mode
	config.m_crypto_function = "AES-128-ECB";
	config.m_key = std::make_unique<uint8_t[]>(16);
 	memset(config.m_key.get(), 0, 16);
	config.m_key_len = 16;

	assert( encrypt_data  ("homer-simpson.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson_enc_ecb.TGA") );

	assert( decrypt_data  ("homer-simpson_enc_ecb.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson.TGA") );

	assert( encrypt_data  ("UCM8.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8_enc_ecb.TGA") );

	assert( decrypt_data  ("UCM8_enc_ecb.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8.TGA") );

	assert( encrypt_data  ("image_1.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_1_enc_ecb.TGA") );

	assert( encrypt_data  ("image_2.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_2_enc_ecb.TGA") );

	assert( decrypt_data ("image_3_enc_ecb.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_3_dec_ecb.TGA") );

	assert( decrypt_data ("image_4_enc_ecb.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_4_dec_ecb.TGA") );

	// CBC mode
	config.m_crypto_function = "AES-128-CBC";
	config.m_IV = std::make_unique<uint8_t[]>(16);
	config.m_IV_len = 16;
	memset(config.m_IV.get(), 0, 16);

	assert( encrypt_data  ("UCM8.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8_enc_cbc.TGA") );

	assert( decrypt_data  ("UCM8_enc_cbc.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8.TGA") );

	assert( encrypt_data  ("homer-simpson.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson_enc_cbc.TGA") );

	assert( decrypt_data  ("homer-simpson_enc_cbc.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson.TGA") );

	assert( encrypt_data  ("image_1.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_5_enc_cbc.TGA") );

	assert( encrypt_data  ("image_2.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_6_enc_cbc.TGA") );

	assert( decrypt_data ("image_7_enc_cbc.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_7_dec_cbc.TGA") );

	assert( decrypt_data ("image_8_enc_cbc.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_8_dec_cbc.TGA") );
	return 0;
}

#endif /* _PROGTEST_ */
