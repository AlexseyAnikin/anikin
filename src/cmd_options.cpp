#include "cmd_options.h"

#include <boost/program_options.hpp>

#include <iostream>
#include <stdexcept>
#include <string>

namespace CryptoGuard {

namespace po = boost::program_options;

ProgramOptions::ProgramOptions() : command_(COMMAND_TYPE::CHECKSUM), desc_("Allowed options") {}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char* argv[]) 
{
    desc_.add_options()
        ("help,h", "Show help message")
        ("command,c", po::value<std::string>()->required(),
        "Command: encrypt, decrypt, checksum")
        ("input,i", po::value<std::string>(&inputFile_)->required(),
        "Input file path")
        ("output,o", po::value<std::string>(&outputFile_),
        "Output file path")
        ("password,p", po::value<std::string>(&password_),
        "Password for encrypt/decrypt");

    po::variables_map vm;

    try
    {
        po::store(po::parse_command_line(argc, argv, desc_), vm);

        if(vm.contains("help"))
        {
            std::cout << desc_ << '\n';
            throw std::runtime_error{"Help requested"};
        }

        po::notify(vm);

        const std::string command = vm["command"].as<std::string>();

        const auto commandIt = commandMapping_.find(command);
        if(commandIt == commandMapping_.end())
        {
            throw std::runtime_error{"Unsupported command: " + command};
        }

        command_ = commandIt->second;

        if(command_ == COMMAND_TYPE::ENCRYPT || command_ == COMMAND_TYPE::DECRYPT)
        {
            if(outputFile_.empty())
            {
                throw std::runtime_error{"Outout file is required for encrypt/decrypt"};
            }

            if(password_.empty())
            {
                throw std::runtime_error{"Password is required for encrypt/decrypt"};
            }
        }

        if(command_ == COMMAND_TYPE::CHECKSUM && !outputFile_.empty())
        {
            throw std::runtime_error{"Output file is not needed for checksum"};
        }
    } 
    catch(const po::error& e)
    {
        throw std::runtime_error{e.what()};   
    }
}

}  // namespace CryptoGuard
