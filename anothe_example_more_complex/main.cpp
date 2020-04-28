#include <iostream>
#include <system_error>
#include <cstdlib>
#include "hash.h"


int main(int argc, char** argv)
{

    try {
        std::string fileName;
        std::string number;
        FileHash::HashAlg alg = FileHash::MD5;
        std::cout<<"Enter file name ["<<argv[0]<<"]: ";
        getline(std::cin, fileName);
        if (fileName.size() == 0)
            fileName = argv[0];
        std::cout<<"Supported hash algorithms:"<<std::endl;
        std::cout<<"\t  MD2:    "<< FileHash::MD2 <<std::endl;
        std::cout<<"\t  MD4:    "<< FileHash::MD4 <<std::endl;
        std::cout<<"\t  MD5:    "<< FileHash::MD5 <<std::endl;
        std::cout<<"\t  SHA1:   "<< FileHash::SHA1 <<std::endl;
        std::cout<<"\t  SHA256: "<< FileHash::SHA256 <<std::endl;
        std::cout<<"\t  SHA384: "<< FileHash::SHA384 <<std::endl;
        std::cout<<"\t  SHA512: "<< FileHash::SHA512 <<std::endl;
        std::cout<<"Select hash algorithm ["<<alg<<"]: ";
        getline(std::cin, number);
        if (number.size() != 0) {
            unsigned int n = stoul(number);
            alg = (FileHash::HashAlg) n;
        }

        FileHash hash(fileName.data(),  alg);
        std::cout<<"Calculate hash "<<hash.name()<<" for file "<<fileName<<std::endl;
        std::cout<<hash.calcHash()<<std::endl;
    }
    catch (std::system_error& e) {
        std::cerr << e.what()<< " with code " << std::hex << e.code() <<std::endl;
        abort();
    }
    catch (std::logic_error& e) {
        std::terminate();
    }

    return 0;
}

