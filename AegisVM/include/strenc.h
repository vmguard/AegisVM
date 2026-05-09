#pragma once

#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <dpapi.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <cstring>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace anticrack {

    inline std::vector<uint8_t> generate_random_bytes(size_t count) {
        std::vector<uint8_t> bytes(count);
        NTSTATUS status = BCryptGenRandom(
            nullptr,
            bytes.data(),
            static_cast<ULONG>(count),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG
        );
        if (!BCRYPT_SUCCESS(status)) {
            throw std::runtime_error("BCryptGenRandom failed");
        }
        return bytes;
    }

    template<size_t N>
    class XorString {
    private:
        char data[N];
        uint8_t key;
        size_t length;

        // Hash the string bytes to create a unique key per string
        constexpr uint8_t generate_key(const char* str) const {
            uint8_t k = 0xAB;
            for (size_t i = 0; i < N; ++i) {
                k = (k ^ static_cast<uint8_t>(str[i])) * 0x6B;
                k ^= static_cast<uint8_t>(i * 0x35);
            }
            return k ? k : 0xCD;
        }

        constexpr size_t find_length(const char* str) const {
            size_t len = 0;
            while (len < N && str[len] != '\0') ++len;
            return len;
        }

        constexpr void encrypt_data(const char* str) {
            key = generate_key(str);
            length = find_length(str);
            for (size_t i = 0; i < N; ++i) {
                data[i] = str[i] ^ key;
            }
        }

    public:
        constexpr XorString(const char* str) {
            encrypt_data(str);
        }

        std::string decrypt() const {
            std::string result;
            result.reserve(length);
            for (size_t i = 0; i < length; ++i) {
                result += data[i] ^ key;
            }
            return result;
        }
    };

    class SecureString {
    private:
        std::vector<uint8_t> encrypted_data;

        void encrypt_dpapi(const std::string& input) {
            DATA_BLOB plain_blob;
            plain_blob.pbData = reinterpret_cast<BYTE*>(
                const_cast<char*>(input.data())
                );
            plain_blob.cbData = static_cast<DWORD>(input.size());

            DATA_BLOB cipher_blob;
            if (!CryptProtectData(
                &plain_blob,
                nullptr,    
                nullptr,    
                nullptr,      
                nullptr,     
                0,
                &cipher_blob
            )) {
                throw std::runtime_error("CryptProtectData failed");
            }

            encrypted_data.assign(
                cipher_blob.pbData,
                cipher_blob.pbData + cipher_blob.cbData
            );
            LocalFree(cipher_blob.pbData);
        }

    public:
        SecureString(const std::string& input) {
            encrypt_dpapi(input);
        }

        std::string decrypt() const {
            DATA_BLOB cipher_blob;
            cipher_blob.pbData = const_cast<BYTE*>(encrypted_data.data());
            cipher_blob.cbData = static_cast<DWORD>(encrypted_data.size());

            DATA_BLOB plain_blob;
            if (!CryptUnprotectData(
                &cipher_blob,
                nullptr, nullptr, nullptr, nullptr, 0,
                &plain_blob
            )) {
                throw std::runtime_error("CryptUnprotectData failed");
            }

            std::string result(
                reinterpret_cast<char*>(plain_blob.pbData),
                plain_blob.cbData
            );
            SecureZeroMemory(plain_blob.pbData, plain_blob.cbData);
            LocalFree(plain_blob.pbData);
            return result;
        }

        bool verify() const {
            try {
                decrypt();
                return true;
            }
            catch (...) {
                return false;
            }
        }
    };

    class ProtectedString {
    private:
        std::vector<uint8_t> data;
        std::vector<uint8_t> key;

    public:
        ProtectedString(const std::string& input) {
            key = generate_random_bytes(32);
            data.resize(input.size());
            for (size_t i = 0; i < input.size(); ++i) {
                data[i] = static_cast<uint8_t>(input[i]) ^ key[i % key.size()];
            }
        }

        std::string decrypt() const {
            std::string result(data.size(), '\0');
            for (size_t i = 0; i < data.size(); ++i) {
                result[i] = static_cast<char>(data[i] ^ key[i % key.size()]);
            }
            return result;
        }

        void wipe() {
            SecureZeroMemory(data.data(), data.size());
            SecureZeroMemory(key.data(), key.size());
            data.clear();
            key.clear();
        }
    };

    class StringGuard {
    private:
        std::string data;

    public:
        StringGuard(const std::string& str) : data(str) {}
        ~StringGuard() {
            SecureZeroMemory(const_cast<char*>(data.data()), data.size());
        }
        const char* c_str() const { return data.c_str(); }
        operator const char* () const { return data.c_str(); }
    };

#define XOR_STR(str)        (anticrack::XorString<sizeof(str)>(str).decrypt())
#define SECURE_STR(str)     (anticrack::SecureString(str).decrypt())
#define PROTECTED_STR(str)  (anticrack::ProtectedString(str).decrypt())

} // namespace anticrack
