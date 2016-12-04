#include "multyEnc.h"

int main() {

    Encryptor* encryptor = EncryptorFabric::getFileEncryptor(EncType::RC4,
                                                             "/home/zas/Programming/C++/multyEnc/in",
                                                             "/home/zas/Programming/C++/multyEnc/enc",
                                                             "/home/zas/Programming/C++/multyEnc/key",
                                                             true);
    encryptor->encrypt();

    Encryptor* decryptor = EncryptorFabric::getFileEncryptor(EncType::RC4,
                                                             "/home/zas/Programming/C++/multyEnc/enc",
                                                             "/home/zas/Programming/C++/multyEnc/dec",
                                                             "/home/zas/Programming/C++/multyEnc/key");
    decryptor->decrypt();

    return 0;
}