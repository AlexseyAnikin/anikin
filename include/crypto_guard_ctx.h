#pragma once

#include <string>
#include <memory>
#include <string_view>
#include <iosfwd>
#include <istream>
#include <ostream>

namespace CryptoGuard {

class CryptoGuardCtx {
public:
    CryptoGuardCtx();
    ~CryptoGuardCtx();

    CryptoGuardCtx(const CryptoGuardCtx&) = delete;
    CryptoGuardCtx& operator=(const CryptoGuardCtx&) = delete;

    CryptoGuardCtx(CryptoGuardCtx&&) noexcept;
    CryptoGuardCtx& operator=(CryptoGuardCtx&&) noexcept;

    // API
    void EncryptFile(std::istream& inStream, std::ostream& outStream, std::string_view password);
    void DecryptFile(std::istream& inStream, std::ostream& outStream, std::string_view password);
    std::string CalculateChecksum(std::istream& inStream);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

}  // namespace CryptoGuard
