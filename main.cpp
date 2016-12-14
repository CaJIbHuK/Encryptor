#include "multyEnc.h"
#include <iostream>
#include <unordered_map>
#include <math.h>

int MAP_SIZE = 1000;

union Key {
    u_char bytes[8];
    uint64_t key;
};

typedef std::unordered_map<uint64_t , std::vector<u_char>> ciphermap;

void encdec(std::shared_ptr<ContentProvider> dataProvider, Key &currentKey, std::vector<u_char> &result, EncAction action) {
    dataProvider->init();

    std::vector<u_char> key(currentKey.bytes, currentKey.bytes+8);
    auto keyCP = EncryptorFabric::getMemoryContentProvider(key);
    auto cipherCP = EncryptorFabric::getMemoryContentProvider();
    auto desEncryptor = EncryptorFabric::getEncryptor(EncType::DES, dataProvider, cipherCP, keyCP);

    bool res = action == EncAction::ENCRYPT ? desEncryptor->encrypt() : desEncryptor->decrypt();
    cipherCP->read(result);
}

void generateCTMap(ciphermap &CTMap, std::shared_ptr<ContentProvider> plainTextProvider, Key &currentKey, int amount){
    plainTextProvider->init();
    CTMap.clear();
    for (int i = 0; i < amount; ++i) {
        std::vector<u_char> cipher;
        encdec(plainTextProvider, currentKey, cipher, EncAction::ENCRYPT);
        CTMap[currentKey.key] = cipher;
        currentKey.key++;
    }
}


bool bruteForce(std::shared_ptr<ContentProvider> plainTextProvider, std::shared_ptr<ContentProvider> cipherTextProvider, std::vector<u_char> &result) {

    Key currentKey = {.key=0};

    uint64_t endKey = currentKey.key + (uint64_t)pow(2.0, 12.0);

    ciphermap CipherTextMap;
    bool found = false;

    while (!found && currentKey.key < endKey) {
        generateCTMap(CipherTextMap, plainTextProvider, currentKey, MAP_SIZE);
        std::cout << CipherTextMap.size();
        for (auto it = CipherTextMap.begin(); it != CipherTextMap.end(); ++it) {
            Key secondPart = {.key=0};
            while(secondPart.key < endKey){
                std::vector<u_char> decResult;
                encdec(cipherTextProvider, secondPart, decResult, EncAction::DECRYPT);
                found = it->second == decResult;
                if (found) {
                    Key fp = {.key = it->first};
                    result.insert(result.end(), fp.bytes, fp.bytes+8);
                    result.insert(result.end(), secondPart.bytes, secondPart.bytes+8);
                    return true;
                };
                secondPart.key++;
            }
        }
    }


    return false;
}


int main() {

    auto inCP = EncryptorFabric::getFileContentProvider(ContentDirection::In, "/home/zas/Programming/C++/multyEnc/in");
    auto outCP = EncryptorFabric::getFileContentProvider(ContentDirection::Out, "/home/zas/Programming/C++/multyEnc/enc");
//    auto keyCP = EncryptorFabric::getFileContentProvider(ContentDirection::In, "/home/zas/Programming/C++/multyEnc/key");


    std::vector<u_char> vec({9,8,0,0,0,0,0,0,7,6,0,0,0,0,0,0});
    auto keyCP = EncryptorFabric::getMemoryContentProvider(vec);
    std::shared_ptr<Encryptor> encryptor = EncryptorFabric::getEncryptor(EncType::DDES,inCP, outCP, keyCP);
    encryptor->encrypt();

    inCP = EncryptorFabric::getFileContentProvider(ContentDirection::In, "/home/zas/Programming/C++/multyEnc/enc");
    outCP = EncryptorFabric::getFileContentProvider(ContentDirection::Out, "/home/zas/Programming/C++/multyEnc/dec");
//    keyCP = EncryptorFabric::getFileContentProvider(ContentDirection::In, "/home/zas/Programming/C++/multyEnc/
    keyCP->init();
    std::shared_ptr<Encryptor> decryptor = EncryptorFabric::getEncryptor(EncType::DDES,inCP, outCP, keyCP);
    decryptor->decrypt();

    auto plainTextProvider = EncryptorFabric::getFileContentProvider(ContentDirection::In, "/home/zas/Programming/C++/multyEnc/in");
    auto cipherTextProvider = EncryptorFabric::getFileContentProvider(ContentDirection::In, "/home/zas/Programming/C++/multyEnc/enc");

    std::vector<u_char> foundKey;
    bool res = bruteForce(plainTextProvider, cipherTextProvider, foundKey);

    if (!res) {
        std::cout << "DES attack FAILED to find the key :(";
        return 0;
    }

    std::cout << "DES attack SUCCEEDED!" << std::endl;
    std::cout << "==========KEY========" << std::endl;
    for (auto it = foundKey.begin(); it != foundKey.end(); ++it) {
        std::cout << (*it);
    }

    return 0;
}