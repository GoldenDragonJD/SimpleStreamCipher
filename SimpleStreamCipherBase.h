#pragma once
#include <vector>
#include <cstdint>
#include <cstring>
#include <string>
#include <functional>

class SimpleStreamCipher {
public:
    SimpleStreamCipher(const std::vector<uint8_t>& key,
                       const std::vector<uint8_t>& nonce)
        : m_key(key), m_nonce(nonce), m_counter(0) {}

    // Encrypts OR decrypts in-place
    void process(uint8_t* data, size_t length) {
        size_t offset = 0;

        while (offset < length) {
            std::vector<uint8_t> keystream = generateKeystreamBlock();

            for (size_t i = 0; i < keystream.size() && offset < length; ++i) {
                data[offset++] ^= keystream[i];
            }
        }
    }

private:
    std::vector<uint8_t> m_key;
    std::vector<uint8_t> m_nonce;
    uint64_t m_counter;

    std::vector<uint8_t> generateKeystreamBlock() {
        // Build input buffer: key || nonce || counter
        std::vector<uint8_t> input;
        input.insert(input.end(), m_key.begin(), m_key.end());
        input.insert(input.end(), m_nonce.begin(), m_nonce.end());

        for (int i = 0; i < 8; ++i) {
            input.push_back((m_counter >> (i * 8)) & 0xFF);
        }

        m_counter++;

        // Very simple hash-based keystream (not cryptographically strong)
        std::hash<std::string> hasher;
        std::string s(input.begin(), input.end());
        size_t hash = hasher(s);

        std::vector<uint8_t> stream(32);
        for (size_t i = 0; i < stream.size(); ++i) {
            stream[i] = (hash >> ((i % sizeof(size_t)) * 8)) & 0xFF;
        }

        return stream;
    }
};
