#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>

class FileHash {
private:
    static constexpr int BUF_SIZE = 1024*4;
    std::ifstream f;
    BYTE * buf;
    HCRYPTPROV hCryptProv;
    HCRYPTHASH hHash;
public:
    FileHash()=delete;
    FileHash(const char* fname);
    ~FileHash();
    std::string calcHash();
};


int main()
{
    try {
        FileHash fh("hash.exe");
        std::cout<<fh.calcHash()<<std::endl;
    }
    catch (int e) {
        std::cerr<<e<<std::endl;
        if (e == 1)
            std::cerr<<"Error open file\n";
        else if (e == 2)
            std::cerr<<"Error open crypto context: ";
        else if (e == 3)
            std::cerr<<"Error create hash: ";
        else if (e == 4)
            std::cerr<<"Error eval hash data: ";
        else if (e == 5)
            std::cerr<<"Error get hash value: ";
        if (e != 1)
            std::cerr<<std::hex<<GetLastError()<<std::endl;
        std::terminate();
    }
    return 0;
}


FileHash::FileHash(const char* fname): f(fname, std::ios::binary), buf(new BYTE[BUF_SIZE])
{
    if (!f.good())      //file open?
        throw 1;
    if ( !CryptAcquireContext(&hCryptProv, nullptr, nullptr, PROV_DSS, 0))  //crypto context open?
        throw 2;
    if( !CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash))               //hash handle created?
        throw 3;
}

FileHash::~FileHash()
{
    CryptDestroyHash(hHash);            //destroy hash handle
    CryptReleaseContext(hCryptProv,0);  //close crypto context
    delete[] buf;
}

std::string FileHash::calcHash()
{
    const char HEX_DIG[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
    unsigned long int len;

//calc hash of file
    while (f) {
        f.read( (char*)buf, BUF_SIZE);              //read data portion from file
        len = f.gcount();
        if (!CryptHashData( hHash, buf, len, 0))    //calc hash for data portion
            throw 4;
    }

//get hash
    len = BUF_SIZE;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, buf, &len, 0))
        throw 5;

//convert hash to string
    std::string HashStr;
    for (unsigned int i = 0; i < len; i++) {
        HashStr.push_back(HEX_DIG[buf[i] >> 4]);    //high forth bits
        HashStr.push_back(HEX_DIG[buf[i] & 0xf]);   //low forth bits
    }

    return HashStr;
}
