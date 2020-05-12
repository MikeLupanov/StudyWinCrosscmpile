#include <system_error>
#include <cwchar>
#include "hash.h"

//////////////////////// StringHash ////////////////////////////////////////////

StringHash::StringHash(HashAlg alg): buf(new unsigned char[BUF_SIZE])
{
    status = BCryptOpenAlgorithmProvider(&hAlgorithm, AlgList[alg], nullptr, 0);
    if (status != 0)  //Open provider?
        throw std::system_error(status, std::system_category(), "Error open crypto algorithm provider");
    status = BCryptCreateHash(hAlgorithm, &hHash, nullptr, 0, nullptr, 0, 0);               //hash handle created?
    if (status != 0)
        throw std::system_error(status, std::system_category(), "Error create hash object");
}

StringHash::~StringHash()
{
    delete[] buf;
    BCryptDestroyHash(hHash);            //destroy hash handle
    BCryptCloseAlgorithmProvider(hAlgorithm,0);  //close provider
}

std::string StringHash::name()
{
    wchar_t * p = (wchar_t*)buf;
    std::string res;
    status = BCryptGetProperty(hAlgorithm, BCRYPT_ALGORITHM_NAME, buf, BUF_SIZE, &len, 0);
    if (status != 0)
        throw  std::system_error(status, std::system_category(), "Error get algorithm name");
    for (ULONG i = 0; p[i]!=L'\0'; i++) {
        res.push_back(wctob(p[i]));
    }
    return res;
}

void StringHash::finishHash()
{
//get hash length
    status = BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, buf, BUF_SIZE, &len, 0);
    if (status != 0)
        throw  std::system_error(status, std::system_category(), "Error get hash length");
    len = *(PULONG)buf;
//finalize hash value
    status = BCryptFinishHash(hHash, buf, len, 0);
    if (status != 0)
        throw  std::system_error(status, std::system_category(), "Error get hash value");
}

std::string StringHash::toString()
{
    const char HEX_DIG[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
//convert hash to string
    std::string HashStr;
    for (unsigned int i = 0; i < len; i++) {
        HashStr.push_back(HEX_DIG[buf[i] >> 4]);    //high forth bits
        HashStr.push_back(HEX_DIG[buf[i] & 0xf]);   //low forth bits
    }
    return HashStr;

}

void StringHash::calcHash(const std::string data)
{
//calc hash of
    status = BCryptHashData(hHash, (PUCHAR)data.c_str(), data.length(), 0);
    if (status != 0)    //calc hash for data portion
        throw  std::system_error(status, std::system_category(), "Error evaluate hash data");
}

std::string  StringHash::operator()(const std::string data)
{
    calcHash(data);
    finishHash();
    return toString();
}

//////////////////////// FileHash ////////////////////////////////////////////

void FileHash::calcHash(const std::string data)
{
//open file
    f.exceptions(std::ifstream::failbit | std::ifstream::badbit);
    f.open(data, std::ios::binary);
    f.exceptions(std::ifstream::goodbit );

//calc hash of file
    while (f) {
        f.read( (char*)buf, BUF_SIZE);              //read data portion from file
        len = f.gcount();
        status = BCryptHashData(hHash, (PUCHAR)buf, len, 0);
        if (status != 0)    //calc hash for data portion
            throw  std::system_error(status, std::system_category(), "Error evaluate hash data");
    }
}

