//
//  RC4.cpp
//  RC4Cipher
//
//  Created by Elisabeth Frischknecht on 2/27/24.
//

#include "RC4.hpp"

//constructor
RC4::RC4(std::string key){
    //fill the array:
    for(int k = 0; k < 256; k++){
        S[k] = k;
    }
        
    //shuffle the array
    int j = 0;
    for(int i = 0; i < 256; i++){
        j = (j + S[i] + key[i % key.length()] ) % 256;
        std::swap(S[i], S[j]);
    }
    
    //set things to 0
    this->i = 0;
    this->j = 0;
    
    //fill the keystream
    for(int i = 0; i < 256; i++){
        keystream.push_back(next_byte());
    }
}

uint8_t RC4::next_byte(){
    i = (i + 1) % 256;
    j = (j + S[i]) % 256;
    std::swap(S[i], S[j]);
    
    return S[(S[i] + S[j]) % 256];
}


std::vector<uint8_t> RC4::encrypt(const std::vector<uint8_t>& plaintext){
    std::vector<uint8_t> ciphertext(plaintext.size());
    for(int i = 0; i < plaintext.size(); i++){
        ciphertext[i] = plaintext[i] ^ keystream[i];
    }
    return ciphertext;
}

std::vector<uint8_t> RC4::decrypt(const std::vector<uint8_t>& ciphertext){
    std::vector<uint8_t> plaintext(ciphertext.size());
    for(int i = 0; i < ciphertext.size(); i++){
        plaintext[i] = ciphertext[i] ^ keystream[i];
    }
    return plaintext;
}

std::vector<uint8_t> RC4::getKeyStream(){
    return keystream;
}
