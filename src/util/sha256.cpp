#include "ciphertracedroid/util/sha256.hpp"

#include <openssl/evp.h>

#include <array>
#include <algorithm>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>

namespace ciphertracedroid::util {

bool is_sha256_hex(const std::string& value)
{
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return std::isxdigit(c) != 0;
    });
}

std::string sha256_file(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("could not open file for SHA-256: " + path.string());
    const EVP_MD* algorithm = EVP_sha256();
    EVP_MD_CTX* raw_context = EVP_MD_CTX_new();
    if (raw_context == nullptr) throw std::runtime_error("could not allocate SHA-256 context");
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(raw_context, &EVP_MD_CTX_free);
    if (EVP_DigestInit_ex(context.get(), algorithm, nullptr) != 1) throw std::runtime_error("could not initialize SHA-256");
    std::array<char, 8192> buffer{};
    while (input.read(buffer.data(), buffer.size()) || input.gcount() > 0) {
        if (EVP_DigestUpdate(context.get(), buffer.data(), static_cast<std::size_t>(input.gcount())) != 1) throw std::runtime_error("could not update SHA-256");
    }
    if (!input.eof()) throw std::runtime_error("could not read file for SHA-256: " + path.string());
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_size = 0;
    if (EVP_DigestFinal_ex(context.get(), digest.data(), &digest_size) != 1) throw std::runtime_error("could not finalize SHA-256");
    std::ostringstream output;
    for (unsigned int index = 0; index < digest_size; ++index) output << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(digest[index]);
    return output.str();
}

}  // namespace ciphertracedroid::util
