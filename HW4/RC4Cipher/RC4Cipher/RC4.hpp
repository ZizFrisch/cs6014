//
//  RC4.hpp
//  RC4Cipher
//
//  Created by Elisabeth Frischknecht on 2/27/24.
//

#ifndef RC4_hpp
#define RC4_hpp

#include <stdio.h>
#include <iostream>
#include <algorithm>
#pragma once

class RC4 {
private:
    
    int i;
    int j;
    
    //this holds all of the keys for the keystream
    uint8_t S[256];
    
    //store the generated keystream
    std::vector<uint8_t> keystream;
    
    //next_byte
    uint8_t next_byte();
    
public:
    //constructor
    RC4(std::string key);
    
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext);
    
    std::vector<uint8_t> getKeyStream();
    
};



#endif /* RC4_hpp */
