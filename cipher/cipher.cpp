#include <iostream>
#include <stdexcept>
#include <fstream>
#include <string>
#include <windows.h>

class FileCipher {
private:
    static constexpr int ENCRYPT_BLOCK_SIZE = 64;
    static constexpr int BLOCK_SIZE = 1024 * 4 - 1024 * 4 % ENCRYPT_BLOCK_SIZE;
    static constexpr int BUF_SIZE = BLOCK_SIZE + ENCRYPT_BLOCK_SIZE; //+1 extra-block for block algorithm
    static constexpr int KEYLENGTH = 168<<16;
    BYTE * buf;
    HCRYPTPROV hCryptProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;
public:
    FileCipher()=delete;
    FileCipher(const std::string& password);
    ~FileCipher();
    void encrypt(const std::string& source_file, const std::string& destination_file);
    void decrypt(const std::string& source_file, const std::string& destination_file);
};


int main(int argc, char** argv)
{
    std::ofstream original ("file.original");
    for(int i=0; i<777; ++i)
        original<<"The quick brown fox jumps over the lazy dog"<<std::endl;
    original.close();

    try {
        FileCipher cipher("SuperPa$$w0rd");
        cipher.encrypt("file.original", "file.encrypted");
        cipher.decrypt("file.encrypted", "file.decrypted");
    }
    catch (std::runtime_error& e) {
        std::cerr<<std::hex<<GetLastError()<<std::endl;
        std::terminate();
    }
    return 0;
}


FileCipher::FileCipher(const std::string& password):buf(new BYTE[BUF_SIZE])
{
    bool res = CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0);
    if ( !res)
        if (GetLastError() == (DWORD)NTE_BAD_KEYSET)
            res = CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET);
    if ( !res )
        throw std::runtime_error("crypto context not acquired");
    if ( !CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash))
        throw std::runtime_error("hash handle not created");
    if ( !CryptHashData(hHash, (BYTE *)password.data(), password.size(), 0))
        throw std::runtime_error("hash not calculated");
    if ( !CryptDeriveKey(hCryptProv, CALG_3DES, hHash, KEYLENGTH, &hKey))
        throw std::runtime_error("key not derived");
}

FileCipher::~FileCipher()
{
    CryptDestroyHash(hHash);            //destroy hash object
    CryptDestroyKey(hKey);              //destroy key object
    CryptReleaseContext(hCryptProv,0);  //release crypto context
    delete[] buf;
}

void FileCipher::encrypt(const std::string& source_file, const std::string& destination_file)
{
    unsigned long int len;
    std::ifstream source(source_file, std::ios::binary | std::ios::in );
    if(!source)
        throw std::runtime_error("encrypt source file failed");
    std::ofstream destination(destination_file,std::ios::binary | std::ios::out);
    if(!destination)
        throw std::runtime_error("encrypt destination file failed");

//encrypt
    while (source) {
        source.read( (char*)buf, BLOCK_SIZE);              //read data portion from file
        len = source.gcount();
        if (!CryptEncrypt(hKey, 0, len < BLOCK_SIZE, 0, buf, &len, BLOCK_SIZE))   //encrypt data portion
            throw std::runtime_error("block not encrypted");
        destination.write((char*)buf, len);
    }

}

void FileCipher::decrypt(const std::string& source_file, const std::string& destination_file)
{
    unsigned long int len;
    std::ifstream source(source_file, std::ios::binary | std::ios::in );
    if(!source)
        throw std::runtime_error("decrypt source file failed");
    std::ofstream destination(destination_file,std::ios::binary | std::ios::out);
    if(!destination)
        throw std::runtime_error("decrypt destination file failed");

//decrypt
    while (source) {
        source.read( (char*)buf, BLOCK_SIZE);              //read data portion from file
        len = source.gcount();
        if (!CryptDecrypt( hKey, 0, len < BLOCK_SIZE, 0, buf, &len))    //decrypt data portion
            throw std::runtime_error("block not decrypted");
        destination.write((char*)buf, len);
    }

}
