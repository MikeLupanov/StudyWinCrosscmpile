#include <iostream>
#include <iomanip>
#include <system_error>
#include <cstdlib>
#include "hash.h"
#include "cipher.h"

void cipher_file()
{
    const std::string orig_file("file.original");
    const std::string encr_file("file.encrypted");
    const std::string decr_file("file.decrypted");
    std::ofstream original (orig_file);
    original<<"The quick brown fox jumps over the lazy dog"<<std::endl;
    original.close();
    std::string psw = "SuperPa$$w0rd";
    try {
        Cipher::CipherAlg alg = Cipher::_3DES;
        std::cout<<"Supported cipher algorithms:"<<std::endl;
        std::cout<<"\t  3DES:   "<< Cipher::_3DES <<std::endl;
        std::cout<<"\t  AES:    "<< Cipher::AES <<std::endl;
        std::cout<<"\t  DES:    "<< Cipher::DES <<std::endl;
        std::cout<<"\t  RC2:    "<< Cipher::RC2 <<std::endl;
        std::cout<<"Select hash algorithm ["<<alg<<"]: ";
        std::string input_value;
        getline(std::cin, input_value);
        if (input_value.size() != 0) {
            alg = (Cipher::CipherAlg) stoul(input_value);
        }
        FileCipher cipher(psw,alg);
        cipher.encrypt(orig_file, encr_file);
        cipher.decrypt(encr_file, decr_file);
        std::cout<<"Used algoruthm: "<<cipher.name()<<std::endl;
        std::cout<<"\nOriginal message "<<orig_file<<":\n";
        std::ifstream f(orig_file);
        getline(f,input_value);
        f.close();
        std::cout << input_value <<std::endl;
        std::cout<<"\nEncrypted message "<<encr_file<<":";
        f.open(encr_file, std::ios::binary | std::ios::in);
        std::cout<<std::hex<<std::setfill('0');
        int i = 0;
        while (true) {
            unsigned c = f.get();
            if (f.eof())
                break;
            if (i % 16 == 0)
                std::cout<<std::endl;
            else if (i % 8  == 0)
                std::cout<<' ';
            std::cout<<std::setw(2)<<c<<' ';
            i++;
        }
        f.close();
        std::cout<<"\n\nDecrypted message "<<decr_file<<":\n";
        f.open(decr_file);
        getline(f,input_value);
        f.close();
        std::cout << input_value <<std::endl;

    }
    catch (std::system_error& e) {
        std::cerr << e.what()<< " with code " << std::hex << e.code() <<std::endl;
        abort();
    }
    catch (std::logic_error& e) {
        std::terminate();
    }
}
void hash_file(const char* default_file)
{
    try {
        std::string fileName;
        std::string number;
        Hash::HashAlg alg = Hash::MD5;
        std::cout<<"Enter file name ["<<default_file<<"]: ";
        getline(std::cin, fileName);
        if (fileName.size() == 0)
            fileName = default_file;
        std::cout<<"Supported hash algorithms:"<<std::endl;
        std::cout<<"\t  MD2:    "<< Hash::MD2 <<std::endl;
        std::cout<<"\t  MD4:    "<< Hash::MD4 <<std::endl;
        std::cout<<"\t  MD5:    "<< Hash::MD5 <<std::endl;
        std::cout<<"\t  SHA1:   "<< Hash::SHA1 <<std::endl;
        std::cout<<"\t  SHA256: "<< Hash::SHA256 <<std::endl;
        std::cout<<"\t  SHA384: "<< Hash::SHA384 <<std::endl;
        std::cout<<"\t  SHA512: "<< Hash::SHA512 <<std::endl;
        std::cout<<"Select hash algorithm ["<<alg<<"]: ";
        getline(std::cin, number);
        if (number.size() != 0) {
            alg = (Hash::HashAlg) stoul(number);
        }

        FileHash hash(alg);
        std::cout<<"Calculate hash "<<hash.name()<<" for file \'"<<fileName<<"\'"<<std::endl;
        std::cout<<hash(fileName)<<std::endl;
        StringHash s_hash;
        std::string s = "Hello, world";
        std::cout<<"Bonus!!!\nCalculate hash "<<s_hash.name()<<" for string \'"<<s<<"\'"<<std::endl;
        std::cout<<s_hash(s)<<std::endl;
    }
    catch (std::system_error& e) {
        std::cerr << e.what()<< " with code " << std::hex << e.code() <<std::endl;
        abort();
    }
    catch (std::logic_error& e) {
        std::terminate();
    }
}

int main(int argc, char** argv)
{

    unsigned n = 1;
    std::string number;
    std::cout<<"Supported demo functions:"<<std::endl;
    std::cout<<"\t  calculate hash:   1"<<std::endl;
    std::cout<<"\t  encrypt/decrypt:  2"<<std::endl;
    std::cout<<"Select demo ["<<n<<"]: ";
    getline(std::cin, number);
    if (number.size() != 0) {
        n = stoul(number);
    }
    if (n==2)
        cipher_file();
    else
        hash_file(argv[0]);

    return 0;
}

