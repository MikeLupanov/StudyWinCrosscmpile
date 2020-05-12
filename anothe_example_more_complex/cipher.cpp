#include <system_error>
#include <cwchar>
#include "cipher.h"
#include "hash.h"
//////////////////////////////////////Cipher///////////////////////////////////////////////////
Cipher::Cipher(const std::string password, CipherAlg alg)
{
    // hash password
    std::string psw_hash;
    {
        StringHash hash(Hash::SHA256);
        psw_hash = hash(password);
    }

    ULONG len;

    // open provider
    status = BCryptOpenAlgorithmProvider(&hAlg, AlgList[alg], nullptr, 0);
    if (status != 0)  //Open provider?
        throw std::system_error(status, std::system_category(), "Error open crypto algorithm provider");

    // get key object len
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&KeyObjLen, sizeof(DWORD), &len, 0);
    if (status != 0)
        throw std::system_error(status, std::system_category(), "Error get key object length");
    KeyObj = new BYTE[KeyObjLen];

    // get algorithm block len
    status = BCryptGetProperty(hAlg, BCRYPT_BLOCK_LENGTH, (PBYTE)&BlockLen, sizeof(DWORD), &len, 0);
    if (status != 0)
        throw std::system_error(status, std::system_category(), "Error get block length");
    
    // set CBC mode
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (status != 0)
        throw std::system_error(status, std::system_category(), "Error set CBC mode");

    // generate key
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, KeyObj, KeyObjLen, (PBYTE)psw_hash.data(), psw_hash.size(), 0);
    if (status != 0)
        throw std::system_error(status, std::system_category(), "Error generate key");
}

Cipher::~Cipher()
{
    delete[] KeyObj;
    delete[] IV;
    BCryptDestroyKey(hKey);            //destroy hash handle
    BCryptCloseAlgorithmProvider(hAlg,0);  //close provider
}

std::string Cipher::name()
{
    constexpr int BUF_SIZE = 1024;
    ULONG len;
    PBYTE buf = new BYTE[BUF_SIZE];
    wchar_t * p = (wchar_t*)buf;
    std::string res;
    status = BCryptGetProperty(hAlg, BCRYPT_ALGORITHM_NAME, buf, BUF_SIZE, &len, 0);
    if (status != 0)
        throw  std::system_error(status, std::system_category(), "Error get algorithm name");

    for (ULONG i = 0; p[i]!=L'\0'; i++) {
        res.push_back(wctob(p[i]));
    }
    delete[] buf;
    return res;

}

/////////////////////////////////FileCipher//////////////////////////////////////////////////

void FileCipher::encrypt(const std::string& source_file, const std::string& destination_file)
{
    //open files
    std::ifstream source;
    source.exceptions(std::ifstream::failbit | std::ifstream::badbit);
    source.open(source_file, std::ios::binary | std::ios::in);
    source.exceptions(std::ifstream::goodbit );
    std::ofstream destination;
    destination.exceptions(std::ifstream::failbit | std::ifstream::badbit);
    destination.open(destination_file, std::ios::binary | std::ios::out);
    destination.exceptions(std::ifstream::goodbit );

    // init IV by random
    IV = new BYTE[BlockLen]{};
    BCRYPT_ALG_HANDLE hRnd;
    status = BCryptOpenAlgorithmProvider(&hRnd, BCRYPT_RNG_ALGORITHM, nullptr, 0);
    if (status != 0)  //Open provider?
        throw std::system_error(status, std::system_category(), "Error open rnd algorithm provider");
    status = BCryptGenRandom(hRnd, IV, BlockLen, 0);
    if (status != 0)
        throw std::system_error(status, std::system_category(), "Error gen random");
    BCryptCloseAlgorithmProvider(hRnd,0);
    // write IV
    destination.write((char*)IV, BlockLen);
 
    //encrypt
    ULONG len,pad;
    const ULONG in_buf_size = BlockLen*NUM_BLOCKS;
    const ULONG out_buf_size = in_buf_size+BlockLen;
    PBYTE in_buf = new BYTE[in_buf_size];
    PBYTE out_buf = new BYTE[out_buf_size];
    while (source) {
        //read data portion from file
        source.read( (char*)in_buf, in_buf_size);             
        len = source.gcount();
        if (len == 0)
            break;
        if (source.peek() == EOF)
            pad = BCRYPT_BLOCK_PADDING;
        else
            pad = 0;
        //encrypt data portion 
        status = BCryptEncrypt(hKey, in_buf, len, NULL,IV, BlockLen, out_buf, out_buf_size, &len, pad );
        if (status != 0)
            throw std::system_error(status, std::system_category(),"block not encrypted");
        //write data portion to file
        destination.write((char*)out_buf, len);
    }
}

void FileCipher::decrypt(const std::string& source_file, const std::string& destination_file)
{
    //open files
    std::ifstream source;
    source.exceptions(std::ifstream::failbit | std::ifstream::badbit);
    source.open(source_file, std::ios::binary | std::ios::in);
    source.exceptions(std::ifstream::goodbit );
    std::ofstream destination;
    destination.exceptions(std::ifstream::failbit | std::ifstream::badbit);
    destination.open(destination_file, std::ios::binary | std::ios::out);
    destination.exceptions(std::ifstream::goodbit );
    
    // read IV from random
    IV = new BYTE[BlockLen]{};
    source.read((char*)IV, BlockLen);
 
    //decrypt
    ULONG len,pad;
    const ULONG in_buf_size = BlockLen*NUM_BLOCKS;
    const ULONG out_buf_size = in_buf_size;
    PBYTE in_buf = new BYTE[in_buf_size];
    PBYTE out_buf = new BYTE[out_buf_size];
    while (source) {
        //read data portion from file
        source.read( (char*)in_buf, in_buf_size);             
        len = source.gcount();
        if (len == 0)
            break;
        if (source.peek() == EOF)
            pad = BCRYPT_BLOCK_PADDING;
        else
            pad = 0;
        //decrypt data portion BCRYPT_BLOCK_PADDING
        status = BCryptDecrypt(hKey, in_buf, len, NULL, IV, BlockLen, out_buf, len, &len, pad);
        if (status != 0)
            throw std::system_error(status, std::system_category(), "block not decrypted");
        //write data portion to file
        destination.write((char*)out_buf, len);
    }
}


