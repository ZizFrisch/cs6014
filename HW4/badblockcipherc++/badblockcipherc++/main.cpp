//
//  CS 6014 HW4 programming part 1 - bad block cypher
//  this is similar to an AES cypher but is simplified
//
//  Created by Elisabeth Frischknecht on 2/27/24.
//

#include <iostream>
#include <vector>
#include <algorithm>
#include <random>

using namespace std;
using Block = std::array<uint8_t, 8>;


//generates the key using the given algorithm in the assignment description
Block generateKey(const string& password){
    Block key;
    
    //fill it with zeroes
    for(int i = 0; i < key.size(); i++){
        key[i] = 0;
    }
    
    //fill the key based off of the password
    for(int i = 0; i < password.length(); i++){
        key[i % 8] ^= password[i];
    }
    
    
    return key;
}


//helper method, uses Fisher-Yates shuffle
void shuffleByteArray(std::array<uint8_t, 256>& array){
    random_device rd;
    mt19937 gen(rd());
    for(int i = array.size() -1; i > 0; i--){
        uniform_int_distribution<int> dis(0,1);
        int j = dis(gen);
        swap(array[i], array[j]);
    }
}

//creates the substitution tables by making 8 tables with the numbers 0-255 and then shuffling them
std::array< std::array<uint8_t, 256>, 8> buildSubstitutionTables(){
    std::array< std::array<uint8_t, 256>,8 > substitutionTables;
    for(int i = 0; i < 8; i++){
        for(int j = 0; j < 256; j++){
            substitutionTables[i][j] = j;
        }
        shuffleByteArray(substitutionTables[i]);
    }
    return substitutionTables;
}

//xors each byte of the state with the key
void xorWithKey(vector<uint8_t>& state, const Block& key){
    for(int i = 0; i < state.size(); i++){
        state[i] ^= key[i%8];
    }
}

//shifts all of the bits in the state to the left
void rotateLeft(vector<uint8_t>& state){
    //remember the most significant bit in the first byte
    uint8_t carry = state[0] >> 7;
    
    //shift the bits left by 1 and grab the most significant bit from the next byte and make it the least significant bit of the current byte
    for(int i = 0; i < state.size() -1; i ++){
        state[i] = ( state[i] << 1) | (state[i+1] >> 7);
    }
    
    //make the carried bit the least significant bit of the last byte
    state[state.size() - 1] = (state[state.size() - 1] << 1) | carry;
}


//rotates the entire state right one bit
void rotateRight(vector<uint8_t>& state){
    //remember the least significant bit in the last byte
    uint8_t carry = state[state.size() -1] & 1;
    
    //shift from the back of the state to the front of the state (idk if we had to do it in this order, but did it to be safe)
    for(int i = static_cast<int>(state.size()) - 1; i > 0; i--){
        state[i] = (state[i] >> 1) | ( (state[i-1] & 1) << 7);
    }
    
    //put the carried bit at the front of the first byte of the state
    state[0] = (state[0] >> 1) | (carry << 7 );
}


//encrypts the message
vector<uint8_t> encryptMessage(const vector<uint8_t>& message, const Block& key, const std::array<std::array<uint8_t, 256>,8>& substitutionTables){
    vector<uint8_t> state = message;
    
    for(int round = 0; round < 16; round++){
        //xor the current state with the key
        xorWithKey(state, key);
        
        //substitution with the appropriate table (for round 0, use 0, etc)
        //changes the state to the value in the correct table found at that index
        for (int i = 0; i < state.size(); i++){
            state[i] = substitutionTables[i % 8][state[i]];
        }
        
        //rotate all bits in the state left by 1
        rotateLeft(state);
    }
    return state;
}


//reverse substitution finds the original index we used to get this value in this table
uint8_t reverseSubstitutiion(const std::array<uint8_t, 256>& table, uint8_t b ){
    for(int i = 0; i < table.size(); i++){
        if (table[i] == b){
            return static_cast<uint8_t>(i);
        }
    }
    return b;
}


//decrypt the message by doing the reverse order of operations as encryption
vector<uint8_t> decryptMessage(const vector<uint8_t>& encryptedMessage, const Block& key, const std::array<std::array<uint8_t, 256>,8>& substitutionTables){
    vector<uint8_t> state = encryptedMessage;
    
    for(int round = 0; round < 16; round++){
        //rotate all bits in the current state right by 1
        rotateRight(state);
        
        //substitute in reverse
        for(int i = 0; i < state.size(); i++){
            state[i] = reverseSubstitutiion(substitutionTables[i % 8], state[i]);
        }
        
        //xor the current state with the key
        xorWithKey(state, key);
    }
    return state;
}


//prints the vector to a hex string. Mostly used in debugging
string byteArrayToHexString(const vector<uint8_t>& bytes){
    string hexString;
    for(uint8_t byte : bytes){
        char hexChars[3];
        snprintf(hexChars, sizeof(hexChars), "%02X", byte);
        hexString += hexChars;
    }
    return hexString;
}


int main() {
    string password = "supersecret";
    //cout << "Password is: " << password << endl;
    
    string message = "hello world";
    cout << "Original message: " << message << endl;
    
    Block key = generateKey(password);
    std::array<std::array<uint8_t, 256>,8> substitutionTables = buildSubstitutionTables();
    
    vector<uint8_t> messageBytes(message.begin(), message.end());
    
    vector<uint8_t> encryptedMessage = encryptMessage(messageBytes, key, substitutionTables);
    //cout << "Encrypted message: " << byteArrayToHexString(encryptedMessage) << endl;
    cout << "Encrypted message: ";
    for(int i = 0; i < encryptedMessage.size(); i++){
        cout << encryptedMessage[i];
    }
    cout << endl;
    
    
    vector<uint8_t> decryptedMessage = decryptMessage(encryptedMessage, key, substitutionTables);
    //cout << "Decrypted message: " << byteArrayToHexString(decryptedMessage) << endl;
    cout << "Decrypted Message: ";
    for(int i = 0; i < decryptedMessage.size(); i++){
        cout << decryptedMessage[i];
    }
    cout << endl;
    
    
    //We should not be able to decrypt the message with the wrong key
    string badPassword = "badsecret";
    //cout << "Incorrect password is: " << badPassword << endl;
    Block badKey = generateKey(badPassword);
    vector<uint8_t> badDecryption = decryptMessage(encryptedMessage, badKey, substitutionTables);
    //cout << "Incorrect decrypted message: " << byteArrayToHexString(badDecryption) << endl;
    cout << "Decryption with bad password: ";
    for(int i = 0; i < badDecryption.size(); i++){
        cout << badDecryption[i];
    }
    cout << endl;
    
    //try changing one bit of the encrypted message using xor
    //gives "garbage" output after decryption with the correct key.
    //some of the output is correct (maybe I can see the "h", and the "ld", sometimes "world" comes through) depending on the randomized tables.
    //So maybe only part of the decryption is garbled.
    encryptedMessage[0] ^= 1;
    vector<uint8_t> changedDecryption = decryptMessage(encryptedMessage, key, substitutionTables);
    //cout << "Decrypted message: " << byteArrayToHexString(decryptedMessage) << endl;
    cout << "Decrypted Message with Flipped Bit: ";
    for(int i = 0; i < changedDecryption.size(); i++){
        cout << changedDecryption[i];
    }
    cout << endl;
    
    
    
}
