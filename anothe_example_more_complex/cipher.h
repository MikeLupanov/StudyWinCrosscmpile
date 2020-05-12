#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <windows.h>

class Cipher {
public:
    enum CipherAlg {_3DES, AES, DES, RC2};

protected:
    std::map<int,const wchar_t*> AlgList {
        std::pair<int,const wchar_t*>(_3DES,BCRYPT_3DES_ALGORITHM),
        std::pair<int,const wchar_t*>(AES,BCRYPT_AES_ALGORITHM),
        std::pair<int,const wchar_t*>(DES,BCRYPT_DES_ALGORITHM),
        std::pair<int,const wchar_t*>(RC2,BCRYPT_RC2_ALGORITHM)
    };
    static constexpr int NUM_BLOCKS = 1024;
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_HASH_HANDLE hHash;
    BCRYPT_KEY_HANDLE hKey;
    ULONG KeyObjLen;
    ULONG BlockLen;
    PBYTE KeyObj;
    PBYTE IV;
    NTSTATUS status;
public:
    Cipher()=delete;
    Cipher(const std::string password, CipherAlg alg = _3DES);
    virtual ~Cipher();
    std::string name();
};

class FileCipher:public Cipher {
public:
    FileCipher()=delete;
    FileCipher(const std::string password, CipherAlg alg = _3DES):Cipher(password, alg){}
    ~FileCipher(){}
    void encrypt(const std::string& source_file, const std::string& destination_file);
    void decrypt(const std::string& source_file, const std::string& destination_file);
};
