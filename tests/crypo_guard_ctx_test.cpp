#include "crypto_guard_ctx.h"

#include <gtest/gtest.h>

#include <sstream>
#include <stdexcept>
#include <string>

namespace
{
    constexpr std::string_view kPassword = "strong_password_123";
    constexpr std::string_view kWrongPassword = "wrong_password";
} // namespace

TEST(CryptoGuardCtxTest, CalculateCheckSumForHello)
{
    CryptoGuard::CryptoGuardCtx cryptoCtx;

    std::stringstream input;
    input << "hello";

    const std::string checkSum = cryptoCtx.CalculateChecksum(input);
    EXPECT_EQ(
        checkSum,
        "2cf24dba5fb0a30e26e83b2ac5b9e29e"
        "1b161e5c1fa7425e73043362938b9824"
    );
}

TEST(CryptoGuardCtxTest, EncryptoDecryptoReturnsOriginalText)
{
    CryptoGuard::CryptoGuardCtx cryptoCtx;

    const std::string originalText = 
        "Hello, CryptoGuard!\n"
        "This text should be encrypted and decrypted correctly.";

    std::stringstream input;
    std::stringstream encrypted;
    std::stringstream decrypted;

    input << originalText;

    cryptoCtx.EncryptFile(input, encrypted, kPassword);

    ASSERT_FALSE(encrypted.str().empty());
    EXPECT_NE(encrypted.str(), originalText);

    cryptoCtx.DecryptFile(encrypted, decrypted, kPassword);

    EXPECT_EQ(decrypted.str(), originalText);
}

TEST(CryptoGuardCtxTest, EncryptDecryptWorksWithEmptyInput) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;

    std::stringstream input;
    std::stringstream encrypted;
    std::stringstream decrypted;

    cryptoCtx.EncryptFile(input, encrypted, kPassword);

    ASSERT_FALSE(encrypted.str().empty());

    cryptoCtx.DecryptFile(encrypted, decrypted, kPassword);

    EXPECT_EQ(decrypted.str(), "");
}

TEST(CryptoGuardCtxTest, DecryptWithWrongPasswordThrows) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;

    std::stringstream input;
    std::stringstream encrypted;
    std::stringstream decrypted;

    input << "Secret message";

    cryptoCtx.EncryptFile(input, encrypted, kPassword);

    EXPECT_THROW(
        cryptoCtx.DecryptFile(encrypted, decrypted, kWrongPassword),
        std::runtime_error
    );
}

TEST(CryptoGuardCtxTest, EncryptWithEmptyPasswordThrows) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;

    std::stringstream input;
    std::stringstream encrypted;

    input << "Some text";

    EXPECT_THROW(
        cryptoCtx.EncryptFile(input, encrypted, ""),
        std::runtime_error
    );
}

TEST(CryptoGuardCtxTest, DecryptWithEmptyPasswordThrows) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;

    std::stringstream input;
    std::stringstream decrypted;

    input << "Some encrypted data";

    EXPECT_THROW(
        cryptoCtx.DecryptFile(input, decrypted, ""),
        std::runtime_error
    );
}