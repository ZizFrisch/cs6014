//
//  main.cpp
//  RC4Cipher
//
//  Created by Elisabeth Frischknecht on 2/27/24.
//

#include <iostream>
#include "RC4.hpp"

//a helper method for printing things
void printBytes(const std::vector<uint8_t>& text){
    for( uint8_t byte : text){
        std::cout << static_cast<char>(byte);
    }
    std::cout << std::endl;
}

void printBytesAsHex(const std::vector<uint8_t>& text){
    for( uint8_t byte : text){
        std::cout << std::hex << static_cast<int>(byte) << " ";
    }
    std::cout << std::endl;
}

int main(int argc, const char * argv[]) {
    //generate a key and cipher table
    std::string key = "Secret";
    RC4 cipher(key);
        
    std::string plaintext = "Attack at dawn";
    std::vector<uint8_t> plaintext_bytes(plaintext.begin(), plaintext.end());
    
    //encrypt
    std::vector<uint8_t> ciphertext = cipher.encrypt(plaintext_bytes);
    
    //decrypt
    std::vector<uint8_t> decrypted_plaintext = cipher.decrypt(ciphertext);
    
    

        
    //generate a new key and cipher table
    std::string badKey = "SuperSecret";
    RC4 badcipher(badKey);
    std::vector<uint8_t> bad_decrypted_text = badcipher.decrypt(ciphertext);
    
    std::cout << "\n\n**Showing that decryption with a different key than encryption does not reveal plaintext**\n";
    
    std::cout << "plaintext: " << plaintext << std::endl;
    
    //note: I am printing this as hex to compare it to the examples on the wikipedia article for this algorithm: https://en.wikipedia.org/wiki/RC4#Test_vectors
    //with the key "Secret", Attack at dawn should be 45A01F645FC35B383552544B9BF5 when encrypted
    std::cout << "ciphertext: ";
    printBytesAsHex(ciphertext);
    
    std::cout << "Decrypted plaintext: ";
    printBytes(decrypted_plaintext);
    
    std::cout << "Decrypted plaintext with wrong key: ";
    printBytes(bad_decrypted_text);
    
    std::cout << "Decrypted plaintext as hex: \n";
    printBytesAsHex(decrypted_plaintext);
    
    std::cout << "Decrypted plaintext with wrong key as hex: \n";
    printBytesAsHex(bad_decrypted_text);
    
    
    //is using the same keystream twice insecure? try for the words "hello" and "world"
    std::cout << "\n\n\n**Now using the same key to encrypt two messages:\n";
    
    std::string plaintextHello = "hello";
    std::vector<uint8_t> plaintext_bytesHello(plaintextHello.begin(), plaintextHello.end());
    
    //encrypt
    std::vector<uint8_t> ciphertextHello = cipher.encrypt(plaintext_bytesHello);
    
    //decrypt
    std::vector<uint8_t> decrypted_plaintextHello = cipher.decrypt(ciphertextHello);
    
    std::string plaintextWorld = "world";
    std::vector<uint8_t> plaintext_bytesWorld(plaintextWorld.begin(), plaintextWorld.end());
    
    //encrypt
    std::vector<uint8_t> ciphertextWorld = cipher.encrypt(plaintext_bytesWorld);
    
    //decrypt
    std::vector<uint8_t> decrypted_plaintextWorld = cipher.decrypt(ciphertextWorld);
    
    
    //print the results for encrypting hello and world
    std::cout << "plaintext: " << plaintextHello << std::endl;
    std::cout << "ciphertext: ";
    printBytesAsHex(ciphertextHello);
    
    std::cout << "plaintext: " << plaintextWorld << std::endl;
    std::cout << "ciphertext: ";
    printBytesAsHex(ciphertextWorld);
    
    //what do we get if we xor the two things?
    std::vector<uint8_t> encryptionXOR;
    for(int i = 0; i < ciphertextHello.size(); i++){
        encryptionXOR.push_back(ciphertextHello[i] ^ ciphertextWorld[i]);
    }
    
    std::vector<uint8_t> plaintextXOR;
    for(int i = 0; i < plaintext_bytesHello.size(); i++){
        plaintextXOR.push_back(plaintext_bytesHello[i] ^ plaintext_bytesWorld[i]);
    }
    
    
    std::cout << "the two encrypted messages xor'd together: \n";
    printBytesAsHex(encryptionXOR);
    std::cout << "the two plaintext messages xor'd together: \n";
    printBytesAsHex(plaintextXOR);
    
    
    std::cout<<"\n\n\n**Attempting bit flipping attack: \n";
    plaintext = "Your salary is $1000";
    std::vector<uint8_t> plaintext_bytesBitAttack(plaintext.begin(), plaintext.end());
    
    //encrypt
    ciphertext = cipher.encrypt(plaintext_bytesBitAttack);
    
    //decrypt
    decrypted_plaintext = cipher.decrypt(ciphertext);
    std::cout << "plaintext: " << plaintext << std::endl;
//    std::cout << "ciphertext, not attacked: ";
//    printBytesAsHex(ciphertext);
    std::cout << "decrypted plaintext: ";
    printBytes(decrypted_plaintext);
    
    //ATTACK!
    //bytes 16-19 need to change.
    ciphertext[16] ^= 8;
    for(int i = 17; i <= 19; i++){
        ciphertext[i] ^= 9;
    }
    
    std::vector<uint8_t> attacked_decription = cipher.decrypt(ciphertext);
    std::cout << "Decrypted attacked message: ";
    printBytes(attacked_decription);

    return 0;
    

}
