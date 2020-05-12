#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <windows.h>

class Hash {
public:
    enum HashAlg {MD2, MD4, MD5, SHA1, SHA256, SHA384, SHA512};
protected:
    std::map<int,const wchar_t*> AlgList {
        std::pair<int,const wchar_t*>(MD5,BCRYPT_MD5_ALGORITHM),
        std::pair<int,const wchar_t*>(MD2,BCRYPT_MD2_ALGORITHM),
        std::pair<int,const wchar_t*>(MD4,BCRYPT_MD4_ALGORITHM),
        std::pair<int,const wchar_t*>(SHA1,BCRYPT_SHA1_ALGORITHM),
        std::pair<int,const wchar_t*>(SHA256,BCRYPT_SHA256_ALGORITHM),
        std::pair<int,const wchar_t*>(SHA384,BCRYPT_SHA384_ALGORITHM),
        std::pair<int,const wchar_t*>(SHA512,BCRYPT_SHA512_ALGORITHM)
    };    
    static constexpr int BUF_SIZE = 1024*4;
    unsigned char * buf;
    ULONG len;
    BCRYPT_ALG_HANDLE hAlgorithm;
    BCRYPT_HASH_HANDLE hHash;
    NTSTATUS status;
    virtual void calcHash(const std::string data)=0;
    void finishHash();
    std::string toString();
    
public:
    Hash()=delete;
    Hash(HashAlg alg = MD5);
    virtual ~Hash();
    std::string operator()(const std::string data);
    std::string name();
};

class StringHash:public Hash {
private:
    virtual void calcHash(const std::string data);
public:
    StringHash()=delete;
    StringHash(HashAlg alg = MD5):Hash(alg) {}
    virtual ~StringHash() {}
};

class FileHash:public Hash {
private:
    virtual void calcHash(const std::string data);
public:
    FileHash()=delete;
    FileHash(HashAlg alg = MD5):Hash(alg) {}
    virtual ~FileHash() {}
};

