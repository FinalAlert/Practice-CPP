#include <crow.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <string>

using namespace CryptoPP;
using namespace std;

AutoSeededRandomPool prng;
SecByteBlock key(AES::DEFAULT_KEYLENGTH);

string pad(const string& text) {
    size_t padLen = AES::BLOCKSIZE - (text.size() % AES::BLOCKSIZE);
    return text + string(padLen, static_cast<char>(padLen));
}

string unpad(const string& text) {
    size_t padLen = static_cast<size_t>(text.back());
    return text.substr(0, text.size() - padLen);
}

string encryptAES(const string& plaintext) {
    string padded = pad(plaintext);
    string ciphertext;
    ECB_Mode<AES>::Encryption encryptor;
    encryptor.SetKey(key, key.size());
    StringSource(padded, true, new StreamTransformationFilter(encryptor, new StringSink(ciphertext)));

    // Кодируем зашифрованные данные в Base64
    string encoded;
    StringSource(ciphertext, true, new Base64Encoder(new StringSink(encoded), false));
    return encoded;
}

string decryptAES(const string& encrypted) {
    // Декодируем данные из Base64
    string decoded;
    StringSource(encrypted, true, new Base64Decoder(new StringSink(decoded)));

    // Дешифруем данные
    string decrypted;
    ECB_Mode<AES>::Decryption decryptor;
    decryptor.SetKey(key, key.size());
    StringSource(decoded, true, new StreamTransformationFilter(decryptor, new StringSink(decrypted)));
    return unpad(decrypted);
}

int main() {
    prng.GenerateBlock(key, key.size());
    crow::SimpleApp app;

    CROW_ROUTE(app, "/encrypt").methods("POST"_method)([](const crow::request& req) {
        auto body = crow::json::load(req.body);
        if (!body) return crow::response(400, "Invalid JSON");
        string plaintext = body["text"].s();
        string encrypted = encryptAES(plaintext);
        return crow::response(crow::json::wvalue({{"encrypted", encrypted}}));
    });

    CROW_ROUTE(app, "/decrypt").methods("POST"_method)([](const crow::request& req) {
        auto body = crow::json::load(req.body);
        if (!body) return crow::response(400, "Invalid JSON");
        string encrypted = body["encrypted"].s();
        string decrypted = decryptAES(encrypted);
        return crow::response(crow::json::wvalue({{"decrypted", decrypted}}));
    });

    CROW_ROUTE(app, "/key").methods("GET"_method)([]() {
        string encoded;
        StringSource(key.data(), key.size(), true, new Base64Encoder(new StringSink(encoded), false));
        return crow::response(crow::json::wvalue({{"key", encoded}}));
    });

    app.port(18080).multithreaded().run();
}
