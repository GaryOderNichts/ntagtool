#include <iostream>
#include <cstdio>
#include <cstdint>
#include <iterator>
#include <optional>

#include <excmd.h>

#include "TagV0.hpp"
#include "TagV2.hpp"
#include "Keys.hpp"
#include "TagEncryption.hpp"

namespace {

constexpr std::size_t kKeyfileSize = 160u;

std::optional<std::vector<std::byte>> ReadBinaryFile(const std::string& path)
{
    auto fp = std::unique_ptr<std::FILE, int(*)(std::FILE*)>(std::fopen(path.c_str(), "rb"), &std::fclose);
    if (!fp) {
        return {};
    }

    std::fseek(fp.get(), 0, SEEK_END);
    long fz = std::ftell(fp.get());
    if (fz == -1l) {
        return {};
    }

    std::fseek(fp.get(), 0, SEEK_SET);

    std::vector<std::byte> buffer(fz);
    std::size_t bytesRead = std::fread(buffer.data(), 1, buffer.size(), fp.get());

    // Truncate buffer if not fully read
    buffer.resize(bytesRead);

    return buffer;
}

bool WriteBinaryFile(const std::string& path, const std::span<const std::byte>& data)
{
    auto fp = std::unique_ptr<std::FILE, int(*)(std::FILE*)>(std::fopen(path.c_str(), "wb"), &std::fclose);
    if (!fp) {
        return false;
    }

    return std::fwrite(data.data(), 1, data.size(), fp.get()) == data.size();
}

}

int main(int argc, char* argv[])
{
    excmd::parser parser;
    excmd::option_state options;

    parser.global_options()
        .add_option("v,version", excmd::description("Show version."))
        .add_option("h,help", excmd::description("Show help."));

    parser.add_command("help")
        .add_argument("help-command", excmd::optional(), excmd::value<std::string>());

    excmd::option_group_adder tagOptionGroup =
        parser.add_option_group("Tag options")
            .add_option("key_file",
                        excmd::description("Path to the key file."),
                        excmd::value<std::string>())
            .add_option("tag_version",
                        excmd::description("Tag version to use."),
                        excmd::value<std::uint32_t>(),
                        excmd::allowed<std::uint32_t>(
                            { 0, 2 }
                        ));

    // TODO
    // parser.add_command("info")
    //     .add_option_group(tagOptionGroup)
    //     .add_argument("tag_file", excmd::description("Path to the tag file."), excmd::value<std::string>());

    // parser.add_command("verify")
    //     .add_option_group(tagOptionGroup)
    //     .add_argument("tag_file", excmd::description("Path to the tag file."), excmd::value<std::string>());

    parser.add_command("encrypt")
        .add_option_group(tagOptionGroup)
        .add_argument("in_file", excmd::description("Path to the decrypted tag file."), excmd::value<std::string>())
        .add_argument("out_file", excmd::description("Path to store the encrypted tag file."), excmd::value<std::string>());

    parser.add_command("decrypt")
        .add_option_group(tagOptionGroup)
        .add_argument("in_file", excmd::description("Path to the encrypted tag file."), excmd::value<std::string>())
        .add_argument("out_file", excmd::description("Path to store the decrypted tag file."), excmd::value<std::string>());

    // TODO
    // parser.add_command("set")
    //     .add_option_group(tagOptionGroup)
    //     .add_argument("tag_file", excmd::description("Path to the tag file."), excmd::value<std::string>());

    try {
        options = parser.parse(argc, argv);
    } catch (const excmd::exception& ex) {
      std::cerr << "Error parsing options: " << ex.what() << std::endl;
      std::exit(-1);
    }

    if (options.has("version")) {
        // TODO
        std::cout << "ntagtool v" VERSION << std::endl;
        std::cout << "Source: https://github.com/GaryOderNichts/ntagtool" << std::endl;
        std::exit(0);
    }

    if (options.empty() || options.has("help")) {
        if (options.has("help-command")) {
            std::cout << parser.format_help(argv[0], options.get<std::string>("help-command")) << std::endl;
        } else {
            std::cout << parser.format_help(argv[0]) << std::endl;
        }
        std::exit(0);
    }

    if (options.has("decrypt") || options.has("encrypt")) {
        const bool decrypt = options.has("decrypt");

        if (!options.has("key_file")) {
            std::cerr << "Missing key_file argument" << std::endl;
            std::exit(-1);
        }

        if (decrypt) {
            std::cout << "Decrypting " << options.get<std::string>("in_file") << " to " << options.get<std::string>("out_file") << std::endl;
        } else {
            std::cout << "Encrypting " << options.get<std::string>("in_file") << " to " << options.get<std::string>("out_file") << std::endl;
        }

        auto tagBuffer = ReadBinaryFile(options.get<std::string>("in_file"));
        if (!tagBuffer) {
            std::cerr << "Failed to read in_file" << std::endl;
            std::exit(-1);
        }

        auto keyBuffer = ReadBinaryFile(options.get<std::string>("key_file"));
        if (!keyBuffer) {
            std::cerr << "Failed to read key_file" << std::endl;
            std::exit(-1);
        }

        if (keyBuffer->size() != kKeyfileSize) {
            std::cerr << "key_file should be " << kKeyfileSize << "bytes in size" << std::endl;
            std::exit(-1);
        }

        std::shared_ptr<Tag> tag{};
        if (options.get<uint32_t>("tag_version") == 0) {
            tag = TagV0::FromBytes(*tagBuffer);
        } else if (options.get<uint32_t>("tag_version") == 2) {
            tag = TagV2::FromBytes(*tagBuffer);
        }

        if (!tag) {
            std::cerr << "Failed to create tag" << std::endl;
            std::exit(-1);
        }

        // TODO we currently don't detect if the tag is encrypted or not
        //      so always assume encrypted/decrypted
        tag->SetEncrypted(decrypt);

        std::shared_ptr<Keys> keys = Keys::FromKeyset(std::span(*keyBuffer).subspan<0, 160>());
        if (!tag) {
            std::cerr << "Failed to create keys" << std::endl;
            std::exit(1);
        }

        TagEncryption te(tag, keys);
        if (!te.InitializeInternalKeys()) {
            std::cerr << "Failed to init internal keys" << std::endl;
            std::exit(1);
        }

        if (decrypt) {
            if (!te.DecryptTag()) {
                std::cerr << "Failed to decrypt tag" << std::endl;
                std::exit(1);
            }

            if (te.ValidateLockedSecretHMAC()) {
                std::cout << "Locked secret HMAC valid" << std::endl;
            } else {
                std::cout << "Locked secret HMAC not valid" << std::endl;
            }

            if (te.ValidateUnfixedInfosHMAC()) {
                std::cout << "Unfixed infos HMAC valid" << std::endl;
            } else {
                std::cout << "Unfixed infos HMAC not valid" << std::endl;
            }
        } else {
            if (te.ValidateLockedSecretHMAC()) {
                std::cout << "Locked secret HMAC valid" << std::endl;
            } else {
                std::cout << "Locked secret HMAC not valid, updating..." << std::endl;
                te.UpdateLockedSecretHMAC();
            }

            if (te.ValidateUnfixedInfosHMAC()) {
                std::cout << "Unfixed infos HMAC valid" << std::endl;
            } else {
                std::cout << "Unfixed infos HMAC not valid, updating..." << std::endl;
                te.UpdateUnfixedInfosHMAC();
            }

            if (!te.EncryptTag()) {
                std::cerr << "Failed to encrypt tag" << std::endl;
                std::exit(1);
            }
        }

        if (!WriteBinaryFile(options.get<std::string>("out_file"), tag->ToBytes())) {
            std::cerr << "Failed to write out_file" << std::endl;
            std::exit(-1);
        }

        std::cout << "Done!" << std::endl;
    }

    return 0;
}
