#include <iostream>
#include <string>
#include <sstream>
#include <cstring>
#include <iomanip>
#include <format>
#include <thread>
#include <../cryptopp/pwdbased.h>
#include <../cryptopp/sha.h>
#include "../include/base64.h"

#define iterations 600000      // DEFAULT ITERATIONS = 600000; 
                               // https://github.com/nextgenhealthcare/connect/blob/be90435c57f2f0e93f1aa612f5afc4bf52717e01/core-models/src/com/mirth/connect/model/EncryptionSettings.java#L34

enum HashParseStatus { Success, InvalidSaltLength };

// ------------------------------------------------------------------
/*!
    Convert a block of data to a hex string
    //copy from https://tweex.net/post/c-anything-tofrom-a-hex-string/
*/
void toHex(
    const void *const data,           //!< Data to convert
    const size_t dataLength,    //!< Length of the data to convert
    std::string &dest           //!< Destination string
    )
{
    const unsigned char     *byteData = reinterpret_cast<const unsigned char*>(data);
    std::stringstream hexStringStream;
    
    hexStringStream << std::hex << std::setfill('0');
    for(size_t index = 0; index < dataLength; ++index)
        hexStringStream << std::setw(2) << static_cast<int>(byteData[index]);
    dest = hexStringStream.str();
}


void convertToBase64(std::string& salt,  std::string& hash){
    salt = base64_encode(salt);
    hash = base64_encode(hash);
}

std::string formatHashcat(const std::string& salt, const std::string& hash){
    return ("sha256:" + std::to_string(iterations) + ":" + salt + ":" + hash);
}

HashParseStatus checkLengthSalt( const std::string& salt){
    return (salt.size() == 12) ? HashParseStatus::Success : HashParseStatus::InvalidSaltLength;
}

bool checkPassword(const std::string& plainPassword, const std::string& encodedHash) {
    std::string decodedBytes = base64_decode(encodedHash);
    
    std::string salt = decodedBytes.substr(0, 8);
    std::string hash = decodedBytes.substr(8);
    
    CryptoPP::byte derived[CryptoPP::SHA256::DIGESTSIZE];
    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf;
    CryptoPP::byte unused = 0;

    pbkdf.DeriveKey(derived, sizeof(derived), unused, reinterpret_cast<const CryptoPP::byte*>(plainPassword.data()), plainPassword.size(), reinterpret_cast<const CryptoPP::byte*>(salt.data()), salt.size(), 600000, 0.0f);
    
    return memcmp(derived, hash.data(), CryptoPP::SHA256::DIGESTSIZE) == 0;
}

std::string prepareHashCat(const std::string& encodedHash) {
    std::string decodedBytes = base64_decode(encodedHash);
    std::string hexString;
    std::string format;

    toHex(decodedBytes.data(), decodedBytes.size(), hexString);
    std::cout << "[#] Full Hex = " << hexString << std::endl;

    std::string salt = decodedBytes.substr(0, 8); 
    std::string hash = decodedBytes.substr(8);
    convertToBase64(salt, hash);
    std::cout << std::format("[#] Salt = {}\n[#] Hash = {}\n[#] Salt Length: {}\n[#] Hash Length: {}\n", salt, hash, salt.size(), hash.size());
    if(checkLengthSalt(salt) != HashParseStatus::Success){
        std::cerr << "[-] SALT Length must be 12 (8-byte salt encoded as Base64)\n";   // private static final int SALT_LENGTH = 12;
                                                                                      // https://github.com/nextgenhealthcare/connect/blob/be90435c57f2f0e93f1aa612f5afc4bf52717e01/server/src/com/mirth/connect/server/util/Pre22PasswordChecker.java#L20
        return "";
    }
    format = formatHashcat(salt, hash);
    return format;
}

void usage(char* program)
{
    std::cout << "\nUsage:\n"
              << "  " << program << " <HASH>\n\n"
              << "Example:\n"
              << "  " << program << " b8cA3mDkavInMc2JBYa6/C3EGxDp7ppqh7FsoXx0x8+3LWK3Ed3ELg==\n\n";
}

int main (int argc, char* argv[]) {
    try {
        
        if (argc < 2) {
            usage(argv[0]);
             return 1;
        }

        std::string hash = argv[1];
        std::string format = prepareHashCat(hash);
        if (format.empty()) return 1;
        std::cout << std::format("\n[$] echo \"{}\" > hash && hashcat -m 10900 hash /usr/share/wordlists/rockyou.txt\n", format);
        
        // To manually verify a password, uncomment the lines below:
        
        /* std::string password = "admin";
        if(checkPassword(password, hash)){
            std::cout << std::format("[+] Password Found: {}\n", password);
        }else{
             std::cout << std::format("[-] Not Matched: {}\n", password);
        } */

    }catch(const std::exception& e){
        std::cerr << e.what() << '\n';
    }
    return 0;
}