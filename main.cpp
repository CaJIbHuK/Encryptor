#include "multyEnc.h"

std::vector<u_char> bruteForce(std::vector<u_char> &plainText, std::vector<u_char> &cipherText) {
    std::shared_ptr<Encryptor> encryptor = EncryptorFabric::getFileEncryptor(EncType::DES,
                                                                             "/home/zas/Programming/C++/multyEnc/in",
                                                                             "/home/zas/Programming/C++/multyEnc/enc",
                                                                             "/home/zas/Programming/C++/multyEnc/key",
                                                                             true);



}


int main() {

    std::shared_ptr<Encryptor> encryptor = EncryptorFabric::getFileEncryptor(EncType::DDES,
                                                             "/home/zas/Programming/C++/multyEnc/in",
                                                             "/home/zas/Programming/C++/multyEnc/enc",
                                                             "/home/zas/Programming/C++/multyEnc/key",
                                                             true);
    encryptor->encrypt();
//    std::shared_ptr<ContentProvider> plainTextProvider = EncryptorFabric::getContentProvider(ContentProviderType::File, ContentDirection::In, "/home/zas/Programming/C++/multyEnc/in");
//    std::shared_ptr<ContentProvider> cipherTextProvider = EncryptorFabric::getContentProvider(ContentProviderType::File, ContentDirection::In, "/home/zas/Programming/C++/multyEnc/enc");
//
//    std::vector<u_char> plainText;
//    std::vector<u_char> cipherText;
//
//    plainTextProvider->read(plainText);
//    cipherTextProvider->read(cipherText);
//
//    bruteForce(plainText, cipherText);
//

    std::shared_ptr<Encryptor> decryptor = EncryptorFabric::getFileEncryptor(EncType::DDES,
                                                             "/home/zas/Programming/C++/multyEnc/enc",
                                                             "/home/zas/Programming/C++/multyEnc/dec",
                                                             "/home/zas/Programming/C++/multyEnc/key");
    decryptor->decrypt();

    return 0;
}