#include "cmd_options.h"
#include "crypto_guard_ctx.h"

#include <fstream>
#include <print>
#include <stdexcept>
#include <string>



int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;

        std::ifstream inputFile(
            options.GetInputFile(),
            std::ios::binary
        );

        if(!inputFile.is_open())
        {
            throw std::runtime_error{"Failed to open input file: " + options.GetInputFile()};
        }

        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT:
        {
            std::ofstream outputFile(
                options.GetOutputFile(),
                std::ios::binary
            );

            if(!outputFile.is_open())
            {
                throw std::runtime_error{"Failed to open output file: " + options.GetOutputFile()};
            }

            cryptoCtx.EncryptFile(
                inputFile,
                outputFile,
                options.GetPassword()
            );
 
            std::print("File encoded successfully\n");
            break;
        }

        case COMMAND_TYPE::DECRYPT:
        {
            std::ofstream outputFile(
                options.GetOutputFile(),
                std::ios::binary
            );

            if(!outputFile.is_open())
            {
                throw std::runtime_error{"Failed to open output file: " + options.GetOutputFile()};
            }

            cryptoCtx.DecryptFile(
                inputFile,
                outputFile,
                options.GetPassword()
            );

            std::print("File decoded successfully\n");
            break;
        }

        case COMMAND_TYPE::CHECKSUM:
        {
            const std::string checkSum = cryptoCtx.CalculateChecksum(inputFile);

            std::print("Checksum: {}\n", checkSum");
            break;
        }

        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}