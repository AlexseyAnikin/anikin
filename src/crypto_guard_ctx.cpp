#include "crypto_guard_ctx.h"

#include <openssl/evp.h>

#include <array>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <iomanip>
#include <sstream>

namespace CryptoGuard {

namespace
{
    struct EvpCipherCtxDeleter
    {
        void opertator()(EVP_CIPHER_CTX* ctx) const noexcept
        {
            if(ctx != nullptr)
            {
                EVP_CIPHER_CTX_free(ctx);
            }
        }
    };

    struct EvpMdCtxDeleter
    {
        void operator()(EVP_MD_CTX* ctx) const noexcept
        {
            if(ctx != nullptr)
            {
                EVP_MD_CTX_free(ctx);
            }
        }
    };
    

    using EvpCipherCtxDeleter = std::unique_ptr<EVP_MD_CTX, EvpCipherCtxDeleter>;
    using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;

    

    EvpMdCtxPtr MakeMdCtx()
    {
        EvpMdCtxPtr ctx{EVP_MD_CTX_new()};

        if(!ctx)
        {
            throw std::runtime_error{"Failed to create EVP_MD_CTX"};
        }
        return ctx;
    }

    struct AesCipherParams
    {
        static constexpr std::size_t KEY_SIZE = 32;
        static constexpr std::size_t IV_SIZE = 16;

        const EVP_CIPHER* cipher = EVP_aes_256_cbc();

        std::array<unsigned char, KEY_SIZE> key{};
        std::array<unsigned char, IV_SIZE> iv{};
    };

    AesCipherParams CreateCipherParamsFromPassword(std::string_view password)
    {
        if(password.empty())
        {
            throw std::runtime_error{"Password is empty!"};
        }

        AesCipherParams params;

        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        const int result = EVP_BytesToKey
        {
            params.cipher,
            EVP_sha256(),
            salt.data(),
            reinterpret_cast<const unsigned char*>(password.data()),
            static_cast<int>(password.size()),
            1,
            params.key.data(),
            params.iv.data()
        };

        if(result == 0)
        {
            throw std::runtime_error{"Failed to create key from passwors"};
        }

        return params;
    }
}

class CryptoGuardCtx::Impl
{
public:
    Impl() 
    {
        OpenSSL_add_all_algorithms();
    }

    ~Impl()
    {
        EVP_cleanup();
    }

    void EncryptFile(std::istream& inStream, std::ostream& outStream, std::string_view password)
    {
        auto params = CreateCipherParamsFromPassword(password);
        auto ctx = MakeCipherCtx();

        constexpr int ENCRYPT_MODE = 1;

        if(EVP_CipherInit_ex(ctx.get(),
                             params.cipher,
                             nullptr,
                             params.key.data(),
                             params.iv.data(),
                             ENCRYPT_MODE) != 1)
                             {
                                throw std::runtime_error{"EVP_CipherInit_ex failed during encryption"};
                             }
        
        constexpr std::size_t BUFFER_SIZE = 4096;

        std::array<unsigned char, BUFFER_SIZE> inBuffer{};
        std::array<unsigned char, BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH> outBuffer{};
        
        while(inStream)
        {
            inStream.read(
                reinterpret_cast<char*>(inBuffer.data()),
                static_cast<std::streamsize>(inBuffer.size())
            );

            const std::streamsize bytesRead = inStream.gcount();

            if(bytesRead <= 0)
            {
                break;
            }

            int outLen = 0;

            if(EVP_CipherUpdate(
                ctx.get(),
                outBuffer.data(),
                &outLen,
                inBuffer.data(),
                static_cast<int>(bytesRead)) != 1)
                {
                    throw std::runtime_error{"EVP_CipherUpdate failed during ebcryption"}
                }

                outStream.write(
                    reinterpret_cast<const char*>(outBuffer.data()),
                    outLen
                );

                if(!outStream)
                {
                    throw std::runtime_error{"Failed to write ebcrypted data"};
                }
        }

        if(!inStream.eof())
        {
            throw std::runtime_error{"Failed to read input data"};
        }

        int finalLen = 0;

        if(EVP_CipherFinal_ex(ctx.get(), outBuffer.data(), &finalLen) != 1)
        {
            throw std::runtime_error{"EVP_CipherFinal_ex failed during encryption"};
        }

        outStream.write(
            reinterpret_cast<const char*>(outBuffer.data()),
            finalLen
        );

        if(!outStream)
        {
            throw std::runtime_error{"Failed to write final encrypted block"};
        }

    }

    void DecryptFile(std::istream& inStream, std::ostream& outStream, std::string_view password)
    {
        auto params = CreateCipherParamsFromPassword(password);
        auto ctx = MakeCipherCtx();

        constexpr int DECRYPT_MODE = 0;

        if(EVP_CipherInit_ex(
            ctx.get(),
            params.cipher,
            nullptr,
            params.key.data(),
            params.iv.data(),
            DECRYPT_MODE) != 1)
            {
                throw std::runtime_error{"EVP_CipherInit_ex failed during decryption"}
            }

        constexpr std::size_t BUFFER_SIZE = 4096;

        std::array<unsigned char, BUFFER_SIZE> inBuffer{};
        std::array<unsigned char, BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH> outBuffer{};

        while(inStream)
        {
            inStream.read(
                reinterpret_cast<char*>(inBuffer.data()),
                static_cast<std::streamsize>(inBuffer.size())
            );

            const std::streamsize bytesRead = inStream.gcount();

            if(bytesRead <= 0)
            {
                break;
            }
            
            int  outLen = 0;

            if(EVP_CipherUpdate(
                ctx.get(),
                outBuffer.data(),
                &outLen,
                inBuffer.data(),
                static_cast<int>(bytesRead)) != 1)
                {
                    throw std::runtime_error{"EVP_CipherUpdate failed during decryption"}
                }
            
            outStream.write(
                reinterpret_cast<const char*>(outBuffer.data()),
                outLen
            );

            if(!outStream)
            {
                throw std::runtime_error{"Failed to write decrypted data"};
            }
        }

        if(!inStream.eof())
        {
            throw std::runtime_error{"Failed to read encrypted input data"};
        }

        int finalLen = 0;

        if(EVP_CipherFinal_ex(ctx.get(), outBuffer.data(), &finalLen) != 1)
        {
            throw std::runtime_error{
                "EVP_CipherFinal_ex failed during decryption. Wrong password or corrupted file"
            };
        }

        outStream.write(
            reinterpret_cast<const char*>(outBuffer.data()),
            finalLen
        );

        if(!outStream)
        {
            throw std::runtime_error{"failed to write finaldecrypted block"};
        }
    }

    std::string CalculateChecksum(std::istream& inStream)
    {
        auto ctx = MakeMdCtx();

        if(EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1)
        {
            throw std::runtime_error{"EVP_DigestInit_ex failed"};
        }

        constexpr std::size_t BUFFER_SIZE = 4096;
        std::array<unsigned char, BUFFER_SIZE> buffer{};

        while(inStream)
        {
            inStream.read(
                reinterpret_cast<char*>(buffer.data()),
                static_cast<std::streamsize>(buffer.size())
            );

            const std::streamsize bytesRead = inStream.gcount();

            if(bytesRead <= 0)
            {
                break;
            }

            if(EVP_DigestUpdate(
                ctx.get(),
                buffer.data(),
                static_cast<std::size_t>(bytesRead)) != 1)
                {
                    throw std::runtime_error{"EVP_DigestUpdate failed"};
                }
        }

        if(!inStream.eof())
        {
            throw std::runtime_error{"Failed to read input data for checksum"};
        }

        std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
        unsigned int digestLen = 0;

        if(EVP_DigestFinal_ex(ctx.get(), digest.data(), &digestLen) != 1)
        {
            throw std::runtime_error{"EVP_DigestFinal_ex failed"};
        }

        std::ostringstream result;
        result << std::hex << std::setFill('0');

        for(unsigned int i = 0; i < digestLen; ++i)
        {
            result << std::setw(2) << static_cast<int>(digest[i]);
        }

        return result.str();

    }
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {};

CryptoGuardCtx::~CryptoGuardCtx() = default;

CryptoGuardCtx::CryptoGuardCtx(CryptoGuardCtx&&) noexcept = default;

CryptoGuardCtx& CryptoGuardCtx::operator=(CryptoGuardCtx&&) noexcept = default;

void CryptoGuardCtx::EncryptFile(std::istream& inStream, 
                                 std::ostream& outStream, 
                                 std::string_view password)
{
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::istream& inStream,
                                 std::ostream& outStream,
                                 std::string_view password)
{
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::istream& inStream)
{
    return pImpl_->CalculateChecksum(inStream);
}

}  // namespace CryptoGuard
