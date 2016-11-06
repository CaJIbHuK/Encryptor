#include "multyEnc.h"

int main() {
    Encryptor* encryptor = EncryptorFabric::getFileEncryptor(EncType::OTP,
                                                             "/home/zas/Programming/CPP/multyEnc/in",
                                                             "/home/zas/Programming/CPP/multyEnc/enc",
                                                             "/home/zas/Programming/CPP/multyEnc/key",
                                                             true);
    encryptor->encrypt();

    Encryptor* decryptor = EncryptorFabric::getFileEncryptor(EncType::OTP,
                                                             "/home/zas/Programming/CPP/multyEnc/enc",
                                                             "/home/zas/Programming/CPP/multyEnc/dec",
                                                             "/home/zas/Programming/CPP/multyEnc/key");
    decryptor->decrypt();

    return 0;
}