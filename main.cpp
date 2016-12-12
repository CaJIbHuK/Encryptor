#include "multyEnc.h"

int main() {

    std::shared_ptr<Encryptor> encryptor = EncryptorFabric::getFileEncryptor(EncType::DDES,
                                                             "/home/zas/Programming/C++/multyEnc/in",
                                                             "/home/zas/Programming/C++/multyEnc/enc",
                                                             "/home/zas/Programming/C++/multyEnc/key",
                                                             true);
    encryptor->encrypt();

    std::shared_ptr<Encryptor> decryptor = EncryptorFabric::getFileEncryptor(EncType::DDES,
                                                             "/home/zas/Programming/C++/multyEnc/enc",
                                                             "/home/zas/Programming/C++/multyEnc/dec",
                                                             "/home/zas/Programming/C++/multyEnc/key");
    decryptor->decrypt();

    return 0;
}