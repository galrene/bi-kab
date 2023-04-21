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

class CCipher {
private:
    EVP_CIPHER_CTX * m_Ctx;
    const EVP_CIPHER * m_Cipher;
    struct crypto_config & m_Cfg;

    bool validateConfig () {
        return true;
    }

public:
    CCipher ( struct crypto_config & cfg )
    : m_Ctx ( NULL ), m_Cipher ( NULL ), m_Cfg ( cfg ) {}
    ~CCipher () {

        EVP_CIPHER_CTX_free(m_Ctx);
    }
    /**
     * Validate supplied config, initialise context and given cipher.
     */
    bool init ();

};

bool CCipher::init () {
    if ( ! validateConfig() )
        return false;
    if ( m_Ctx = EVP_CIPHER_CTX_new(); m_Ctx == NULL )
        return false;
    OpenSSL_add_all_ciphers();
    if ( m_Cipher = EVP_get_cipherbyname (m_Cfg.m_crypto_function ); ! m_Cipher )
        return false;
    // enc: 1 encrypt, 0 decrpyt, -1 leave unchanged from prev call
    if ( ! EVP_CipherInit ( m_Ctx, m_Cipher, m_Cfg.m_key.get(), m_Cfg.m_IV.get(), 1 ) )
        return false;
    return true;
}


bool encrypt_data ( const std::string & in_filename, const std::string & out_filename, crypto_config & config ) {
    if ( ! checkConfig ( config ) )
        return false;
    ifstream ifs ( in_filename );
    ofstream ofs ( out_filename );
    if ( ! ifs.good() || ! ofs.good() ) {
        cout << "Unable to open file" << endl;
        return false;
    }
    char header[18] = {0};
    ifs.read ( header, 18 );
    if ( ifs.gcount() != 18 ) {
        cout << "Unable to read header" << endl;
        return false;
    }


    // update in a cycle
    // final
}

bool decrypt_data ( const std::string & in_filename, const std::string & out_filename, crypto_config & config ) {

}


#ifndef __PROGTEST__
// TODO: test for files with different lengths!
bool compare_files ( const char * name1, const char * name2 )
{
    ifstream ifs1 (name1);
    ifstream ifs2 (name2);
    string word;
    string word2;
    while ( ifs1 >> word && ifs2 >> word2 ) {
        if ( word != word2)
            return false;
    }
    if ( word != word2)
        return false;
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
