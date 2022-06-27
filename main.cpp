#include <iostream>
#include <iterator>
#include <random>
#include <iomanip>
#include <exception>
#include <cstdint>
#include <cryptopp/xed25519.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/ripemd.h>
#include <cryptopp/sha3.h>
#include <cryptopp/base32.h>
#include <cryptopp/base64.h>
#include <cpprest/http_client.h>
#include <cpprest/filestream.h>

using namespace web::http;
using namespace web::http::client;
using namespace std;
using namespace CryptoPP;

string toHex(const CryptoPP::byte *source, int length) {
    string dist;
    StringSource (source, length, true,new HexEncoder(new StringSink(dist)));
    return dist;
}
std::string stoh(std::string const& in)
{
    std::ostringstream os;
    for(unsigned char const& c : in)
    {
        os << std::hex << std::setprecision(2) << std::setw(2)
           << std::setfill('0') << static_cast<int>(c);
    }
    return os.str();
}
const CryptoPP::byte ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

int main() {
    // アカウント作成
    AutoSeededRandomPool prng;
    ed25519::Signer signer;
    signer.AccessPrivateKey().GenerateRandom(prng);
    const ed25519PrivateKey& privKey = dynamic_cast<const ed25519PrivateKey&>(signer.GetPrivateKey());
    const CryptoPP::byte* privateKey = privKey.GetPrivateKeyBytePtr();
    const CryptoPP::byte* publicKey = privKey.GetPublicKeyBytePtr();
    string privateKeyHex = toHex(privateKey, 32);
    string publicKeyHex = toHex(publicKey, 32);
    cout << privateKeyHex << endl;
    cout << publicKeyHex << endl;

    // アカウント復元
    string alicePrivateKeyHex = "BBD394D0EE4E10650D5BF15D1389580C6A6C044481E52022A98CD288A2EB679D";
    string alicePrivateKeyBuffer;
    StringSource (alicePrivateKeyHex, true, new HexDecoder(new StringSink(alicePrivateKeyBuffer)));
    ed25519Signer *alice = new ed25519Signer( (const CryptoPP::byte*) alicePrivateKeyBuffer.data());
    const ed25519PrivateKey& alicePrivateKey = dynamic_cast<const ed25519PrivateKey&>(alice->GetPrivateKey());
    const CryptoPP::byte* alicePublicKey = alicePrivateKey.GetPublicKeyBytePtr();
    cout << toHex(alicePrivateKey.GetPrivateKeyBytePtr(), 32) << endl;
    cout << toHex(alicePublicKey, 32) << endl;

    // アドレス導出
    SHA3_256 addressHasher;
    CryptoPP::byte publicKeyHash[CryptoPP::SHA3_256::DIGESTSIZE];
    addressHasher.CalculateDigest(publicKeyHash, alicePublicKey,  32);
    RIPEMD160 addressBodyHasher;
    CryptoPP::byte addressBodyHash[CryptoPP::RIPEMD160::DIGESTSIZE];
    addressBodyHasher.CalculateDigest(addressBodyHash, publicKeyHash, 32);
    SHA3_256 sumHasher;
    CryptoPP::byte sumHash[CryptoPP::SHA3_256::DIGESTSIZE];
    string preSumHashBuffer;
    StringSource ("98" + toHex(addressBodyHash, 32), true, new HexDecoder(new StringSink(preSumHashBuffer)));
    sumHasher.CalculateDigest(sumHash, (const CryptoPP::byte*) preSumHashBuffer.data(), 21);
    string aliceAddressBuffer;
    StringSource ("98" + toHex(addressBodyHash, 20) + toHex(sumHash, 3), true, new HexDecoder(new StringSink(aliceAddressBuffer)));
    string aliceAddress;
    Base32Encoder encoder;
    AlgorithmParameters params = MakeParameters(Name::EncodingLookupArray(),(const CryptoPP::byte *)ALPHABET);
    encoder.IsolatedInitialize(params);
    encoder.Put((const CryptoPP::byte*) aliceAddressBuffer.data(), 24);
    encoder.MessageEnd();
    word64 size = encoder.MaxRetrievable();
    if(size)
    {
        aliceAddress.resize(size);
        encoder.Get((CryptoPP::byte*)&aliceAddress[0], aliceAddress.size());
    }
    cout << aliceAddress << endl;

    // トランザクション構築
    unsigned char version = 1;
    CryptoPP::byte* versionByte = (CryptoPP::byte*) &version;
    unsigned char networkType = 152;
    CryptoPP::byte* networkTypeByte = (CryptoPP::byte*) &networkType;
    unsigned short transactionType = 16724;
    CryptoPP::byte* transactionTypeByte = (CryptoPP::byte*) &transactionType;
    unsigned long fee = 16000;
    CryptoPP::byte* feeByte = (CryptoPP::byte*) &fee;
    unsigned long secondLater7200 = (time(NULL) + 7200 - 1637848847) * 1000;
    CryptoPP::byte* deadline = (CryptoPP::byte*) &secondLater7200;

    string encodedAddress = "TBS2EI4K66LVQ57HMUFXYAJQGIFUR25Z4GTFZUI";
    string decodedAddress;
    Base32Decoder decoder;
    int lookup[256];
    Base64Decoder::InitializeDecodingLookupArray(lookup, ALPHABET, 32, true);
    AlgorithmParameters params2 = MakeParameters(Name::DecodingLookupArray(),(const int *)lookup);
    decoder.IsolatedInitialize(params2);
    decoder.Put( (CryptoPP::byte*)encodedAddress.data(), encodedAddress.size() );
    decoder.MessageEnd();
    word64 size2 = decoder.MaxRetrievable();
    if(size2 && size2 <= SIZE_MAX)
    {
        decodedAddress.resize(size2);
        decoder.Get((CryptoPP::byte*)&decodedAddress[0], decodedAddress.size());
    }
    const CryptoPP::byte* recipientAddress = (const CryptoPP::byte*) decodedAddress.data();

    unsigned char mosaicCount = 1;
    CryptoPP::byte* mosaicCountByte = (CryptoPP::byte*) &mosaicCount;
    unsigned long mosaicId = strtol("3A8416DB2D53B6C8", NULL, 16);
    CryptoPP::byte* mosaicIdByte = (CryptoPP::byte*) &mosaicId;

    unsigned long mosaicAmount = 100;
    CryptoPP::byte* mosaicAmountByte = (CryptoPP::byte*) &mosaicAmount;

    string message = "Hello Symbol!";
    string messageHex = stoh(message);

    unsigned short messageSize = message.length() + 1;
    CryptoPP::byte* messageSizeByte = (CryptoPP::byte*) &messageSize;

    string verifiableBody = toHex(versionByte, 1)
            + toHex(networkTypeByte, 1)
            + toHex(transactionTypeByte, 2)
            + toHex(feeByte, 8)
            + toHex(deadline, 8)
            + toHex(recipientAddress, 24)
            + toHex(messageSizeByte, 2)
            + toHex(mosaicCountByte, 1)
            + "00" + "00000000"
            + toHex(mosaicIdByte, 8)
            + toHex(mosaicAmountByte, 8)
            + "00" + messageHex;
    string verifiableString = "7fccd304802016bebbcd342a332f91ff1f3bb5e902988b352697be245f48e836"
                              + verifiableBody;

    std::string signature;
    string verifiableStringBuffer;
    StringSource(verifiableString, true, new HexDecoder(new StringSink(verifiableStringBuffer)));
    StringSource(verifiableStringBuffer, true, new SignerFilter(NullRNG(), *alice, new StringSink(signature)));
    CryptoPP::byte* signatureByte = (CryptoPP::byte*) signature.data();

    // トランザクション通知
    string verifiableBodyBuffer;
    StringSource(verifiableBody, true, new HexDecoder(new StringSink(verifiableBodyBuffer)));
    unsigned int transactionSize = verifiableBodyBuffer.length() + 108;
    CryptoPP::byte* transactionSizeByte = (CryptoPP::byte*) &transactionSize;

    string payloadString = toHex(transactionSizeByte, 4)
                        + "00000000"
                        + toHex(signatureByte, 64)
                        + toHex(alicePublicKey, 32)
                        + "00000000"
                        + verifiableBody;

    cout << payloadString << endl;

    auto putJson = http_client(U("https://sym-test-02.opening-line.jp:3001"))
            .request(methods::PUT,
                     uri_builder(U("transactions")).to_string(),
                     U("{ \"payload\" : \"" + payloadString + "\"}"),
                     U("application/json"))
            .then([](http_response response) {
                auto json = response.extract_json();
                cout << json.get() << endl;
            });
    try {
        putJson.wait();
    } catch (const std::exception &e) {
        printf("Error exception:%s\n", e.what());
    }

    string hashableBuffer;
    StringSource(toHex(signatureByte, 64) + toHex(alicePublicKey, 32) + verifiableString,
                 true, new HexDecoder(new StringSink(hashableBuffer)));

    SHA3_256 transactionHasher;
    CryptoPP::byte transactionHash[CryptoPP::SHA3_256::DIGESTSIZE];
    const CryptoPP::byte* hashableByte = (const CryptoPP::byte*) hashableBuffer.data();
    transactionHasher.CalculateDigest(transactionHash, hashableByte, hashableBuffer.length());

    cout << "transactionStatus: https://sym-test-02.opening-line.jp:3001/transactionStatus/" << toHex(transactionHash, 32) << endl;
    cout << "confirmed:  https://sym-test-02.opening-line.jp:3001/transactions/confirmed" << toHex(transactionHash, 32) << endl;
    cout << "explorer: https://testnet.symbol.fyi/transactions/" << toHex(transactionHash, 32) << endl;
    return 0;
}
