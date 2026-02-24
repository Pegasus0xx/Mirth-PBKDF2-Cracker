# Mirth-PBKDF2-Cracker

A C++ tool to extract and convert **Mirth Connect** password hashes into a format compatible with **Hashcat**.

---

## How It Works

Mirth Connect stores passwords using **PBKDF2-HMAC-SHA256** with the following structure:

```
Base64( 8-byte salt || SHA256_derived_key )
```

This tool:

1. Decodes the Base64-encoded hash from Mirth Connect
2. Extracts the 8-byte salt and the derived key
3. Re-encodes them separately in Base64
4. Outputs a Hashcat-compatible format: `sha256:<iterations>:<salt>:<hash>`

Default iterations: **600,000** (matching Mirth Connect's default configuration)

---

## Requirements

- **g++** with C++20 support
- **Crypto++** library (`libcryptopp-dev`)
- **Hashcat** (for cracking)

---

## Installation

### 1. Install dependencies

```bash
# Debian / Ubuntu
sudo apt install g++ libcrypto++-dev hashcat

# Arch Linux
sudo pacman -S gcc crypto++ hashcat
```

### 2. Clone the repository

```bash
https://github.com/Pegasus0xx/Mirth-PBKDF2-Cracker.git && \
cd Mirth-PBKDF2-Cracker
```

### 3. Compile

```bash
make
```

---

## Usage

```
./MirthCrack <HASH>
```

Pass the Base64-encoded hash directly as a command-line argument:

```bash
./MirthCrack b8cA3mDkavInMc2JBYa6/C3EGxDp7ppqh7FsoXx0x8+3LWK3Ed3ELg==
```

### Example Output

```
[#] Full Hex = 6fc700de...
[#] Salt = b8cA3g==
[#] Hash = 3mDkav...
[$] echo "sha256:600000:b8cA3g==:3mDkav==" > hash && hashcat -m 10900 hash /usr/share/wordlists/rockyou.txt
```

Copy the generated command and run it with Hashcat.

---

## Password Verification (Optional)

To manually verify a password without Hashcat, uncomment the following block in `main.cpp:110`:

```cpp
std::string password = "admin";
    if(checkPassword(password, hash)){
        std::cout << std::format("[+] Password Found: {}\n", password);
    }else{
        std::cout << std::format("[-] Not Matched: {}\n", password);
}
```

---

## References

- [Mirth Connect - EncryptionSettings.java](https://github.com/nextgenhealthcare/connect/blob/be90435c57f2f0e93f1aa612f5afc4bf52717e01/core-models/src/com/mirth/connect/model/EncryptionSettings.java#L34)
- [Mirth Connect - Pre22PasswordChecker.java](https://github.com/nextgenhealthcare/connect/blob/be90435c57f2f0e93f1aa612f5afc4bf52717e01/server/src/com/mirth/connect/server/util/Pre22PasswordChecker.java)
