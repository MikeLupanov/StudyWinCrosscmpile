#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <windows.h>


class StringHash {
public:
    enum HashAlg {MD2, MD4, MD5, SHA1, SHA256, SHA384, SHA512};
protected:
    static constexpr int BUF_SIZE = 1024*4;
    unsigned char * buf;
    ULONG len;
    std::map<int,const wchar_t*> AlgList {
        std::pair<int,const wchar_t*>(MD5,BCRYPT_MD5_ALGORITHM),
        std::pair<int,const wchar_t*>(MD2,BCRYPT_MD2_ALGORITHM),
        std::pair<int,const wchar_t*>(MD4,BCRYPT_MD4_ALGORITHM),
        std::pair<int,const wchar_t*>(SHA1,BCRYPT_SHA1_ALGORITHM),
        std::pair<int,const wchar_t*>(SHA256,BCRYPT_SHA256_ALGORITHM),
        std::pair<int,const wchar_t*>(SHA384,BCRYPT_SHA384_ALGORITHM),
        std::pair<int,const wchar_t*>(SHA512,BCRYPT_SHA512_ALGORITHM)
    };
    BCRYPT_ALG_HANDLE hAlgorithm;
    BCRYPT_HASH_HANDLE hHash;
    NTSTATUS status;
    virtual void calcHash(const std::string data);
    virtual void finishHash();
    virtual std::string toString();

public:
    StringHash()=delete;
    StringHash(HashAlg alg = MD5);
    virtual ~StringHash();
    std::string operator()(const std::string data);
    std::string name();
};

class FileHash:public StringHash {

private:
    std::ifstream f;
    virtual void calcHash(const std::string data);
public:
    FileHash()=delete;
    FileHash(HashAlg alg = MD5):StringHash(alg) {}
    virtual ~FileHash() {}
};

