#pragma once
#include <QByteArray>
#include <QCryptographicHash>
#include <cstdint>

class SimpleStreamCipher {
public:
    SimpleStreamCipher(const QByteArray& key,
                       const QByteArray& nonce)
        : m_key(key), m_nonce(nonce), m_counter(0) {}

    void process(QByteArray& data) {
        int offset = 0;
        while (offset < data.size()) {
            QByteArray stream = generateKeystreamBlock();
            for (int i = 0; i < stream.size() && offset < data.size(); ++i) {
                data[offset++] ^= stream[i];
            }
        }
    }

private:
    QByteArray m_key;
    QByteArray m_nonce;
    uint64_t   m_counter;

    QByteArray generateKeystreamBlock() {
        QByteArray input;
        input.append(m_key);
        input.append(m_nonce);
        input.append(reinterpret_cast<const char*>(&m_counter),
                     sizeof(m_counter));
        m_counter++;

        return QCryptographicHash::hash(
            input, QCryptographicHash::Sha256
            );
    }
};
