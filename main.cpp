#include "multyEnc.h"
#include <iostream>
#include <map>
#include <math.h>
#include <chrono>

uint64_t MAP_SIZE = (uint64_t)pow(2.0, 24.0);

union Key {
    u_char bytes[8];
    uint64_t key;
};

typedef std::map<std::vector<u_char> , uint64_t> ciphermap;

void encdec(std::shared_ptr<ContentProvider> dataProvider, Key &currentKey, std::vector<u_char> &result, EncAction action) {
    dataProvider->init();

    std::vector<u_char> key(currentKey.bytes, currentKey.bytes+8);
    auto keyCP = EncryptorFabric::getMemoryContentProvider(key);
    auto cipherCP = EncryptorFabric::getMemoryContentProvider();
    auto desEncryptor = EncryptorFabric::getEncryptor(EncType::DES, dataProvider, cipherCP, keyCP);

    bool res = action == EncAction::ENCRYPT ? desEncryptor->encrypt() : desEncryptor->decrypt();
    cipherCP->read(result);
}

void generateCTMap(ciphermap &CTMap, std::shared_ptr<ContentProvider> plainTextProvider, Key &currentKey, uint64_t amount){
    std::cout << "Start generation of table" << std::endl;
    auto start = std::chrono::system_clock::now();
    plainTextProvider->init();
    CTMap.clear();
    for (uint64_t i = 0; i < amount; ++i) {
        std::vector<u_char> cipher;
        encdec(plainTextProvider, currentKey, cipher, EncAction::ENCRYPT);
        CTMap[cipher] = currentKey.key;
        currentKey.key++;
        if (!(i % 100000)) std::cout << "\rGenerated " << i << " of " << amount << " DES ciphers." << std::endl;
    }
    auto finish = std::chrono::system_clock::now();
    std::cout << "Table was generated." << std::endl;
    std::cout << "Duration: " << std::chrono::duration_cast<std::chrono::seconds>(finish - start).count() << "s" << std::endl;
}


bool bruteForce(std::shared_ptr<ContentProvider> plainTextProvider, std::shared_ptr<ContentProvider> cipherTextProvider, std::vector<u_char> &result) {

    Key currentKey = {.key=0};
    uint64_t endKey = currentKey.key + MAP_SIZE;

    ciphermap CipherTextMap;
    generateCTMap(CipherTextMap, plainTextProvider, currentKey, MAP_SIZE);

    std::cout << "Start key search" << std::endl;
    auto start = std::chrono::system_clock::now();
    Key secondPart = {.key=0};
    while (secondPart.key < endKey) {
        std::vector<u_char> decResult;
        encdec(cipherTextProvider, secondPart, decResult, EncAction::DECRYPT);
        auto foundIt = CipherTextMap.find(decResult);
        if (foundIt != CipherTextMap.end()) {
            auto finish = std::chrono::system_clock::now();
            std::cout << "Key was found." << std::endl;
            std::cout << "Duration: " << std::chrono::duration_cast<std::chrono::seconds>(finish - start).count() << "s" << std::endl;
            Key fp = {.key = foundIt->second};
            std::cout << "First part: " << fp.key << std::endl;
            std::cout << "Second part: " << secondPart.key << std::endl;
            result.insert(result.end(), fp.bytes, fp.bytes + 8);
            result.insert(result.end(), secondPart.bytes, secondPart.bytes + 8);
            return true;
        }
        secondPart.key++;
    }

    return false;
}


int main() {

    auto inCP = EncryptorFabric::getFileContentProvider(ContentDirection::In, "/home/zas/Programming/C++/multyEnc/in");
    auto outCP = EncryptorFabric::getFileContentProvider(ContentDirection::Out, "/home/zas/Programming/C++/multyEnc/enc");
    auto keyCP = EncryptorFabric::getMemoryContentProvider({240,240,2,0,0,0,0,0, 100,100,5,0,0,0,0,0});
    std::shared_ptr<Encryptor> encryptor = EncryptorFabric::getEncryptor(EncType::DDES,inCP, outCP, keyCP);
    encryptor->encrypt();

    inCP->init();
    std::vector<u_char> plainText;
    inCP->read(plainText);
    auto plainTextProvider = EncryptorFabric::getMemoryContentProvider(plainText);

    inCP = EncryptorFabric::getFileContentProvider(ContentDirection::In, "/home/zas/Programming/C++/multyEnc/enc");
    outCP = EncryptorFabric::getFileContentProvider(ContentDirection::Out, "/home/zas/Programming/C++/multyEnc/dec");
    keyCP->init();
    std::shared_ptr<Encryptor> decryptor = EncryptorFabric::getEncryptor(EncType::DDES,inCP, outCP, keyCP);
    decryptor->decrypt();

    inCP->init();
    std::vector<u_char> cipherText;
    inCP->read(cipherText);
    auto cipherTextProvider = EncryptorFabric::getMemoryContentProvider(cipherText);

    std::vector<u_char> foundKey;
    bool res = bruteForce(plainTextProvider, cipherTextProvider, foundKey);

    if (!res) {
        std::cout << "DES attack FAILED to find the key :(";
        return 0;
    }

    std::cout << "DES attack SUCCEEDED!" << std::endl;
    std::cout << "==========KEY========" << std::endl;
    std::cout << "Str: ";
    for (auto it = foundKey.begin(); it != foundKey.end(); ++it) {
        std::cout << (*it);
    }
    std::cout << std::endl;
    std::cout << "Bytes: ";
    for (auto it = foundKey.begin(); it != foundKey.end(); ++it) {
        std::cout << (int)(*it) << ' ';
    }

    return 0;
}