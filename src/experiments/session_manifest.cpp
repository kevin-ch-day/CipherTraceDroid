#include "ciphertracedroid/experiments/session_manifest.hpp"
#include "ciphertracedroid/util/sha256.hpp"

#include <cmath>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <unordered_set>

namespace ciphertracedroid::experiments {
namespace {

std::vector<std::string> split_csv(const std::string& line)
{
    std::vector<std::string> fields; std::stringstream stream(line); std::string field;
    while (std::getline(stream, field, ',')) fields.push_back(field);
    return fields;
}

[[noreturn]] void row_error(std::size_t row, const std::string& message)
{
    throw std::runtime_error("manifest row " + std::to_string(row) + ": " + message);
}

ActivityState parse_state(const std::string& value, std::size_t row)
{
    if (value == "foreground") return ActivityState::foreground;
    if (value == "background") return ActivityState::background;
    if (value == "transition") return ActivityState::transition;
    if (value == "device_control") return ActivityState::device_control;
    row_error(row, "invalid state '" + value + "'");
}

double parse_number(const std::string& value, std::size_t row, const std::string& name)
{
    try { const double number = std::stod(value); if (!std::isfinite(number)) row_error(row, name + " must be finite"); return number; }
    catch (const std::exception&) { row_error(row, "invalid " + name); }
}

}  // namespace

std::string to_string(ActivityState state)
{
    switch (state) { case ActivityState::foreground: return "foreground"; case ActivityState::background: return "background"; case ActivityState::transition: return "transition"; case ActivityState::device_control: return "device_control"; }
    throw std::logic_error("unknown activity state");
}

std::vector<SessionManifestRow> read_session_manifest(const std::filesystem::path& path)
{
    std::ifstream input(path); if (!input) throw std::runtime_error("could not open manifest: " + path.string());
    std::string line; if (!std::getline(input, line)) throw std::runtime_error("manifest is empty");
    constexpr std::string_view header = "session_id,app_id,run_id,state,capture_file,capture_sha256,start_offset_s,end_offset_s,include";
    if (line != header) throw std::runtime_error("manifest header does not match required schema");
    std::vector<SessionManifestRow> rows; std::unordered_set<std::string> session_ids; std::size_t number = 1;
    while (std::getline(input, line)) {
        ++number; if (line.empty()) row_error(number, "blank rows are not allowed");
        const auto fields = split_csv(line); if (fields.size() != 9) row_error(number, "expected 9 comma-separated fields");
        if (fields[0].empty() || fields[1].empty() || fields[2].empty() || fields[4].empty()) row_error(number, "session_id, app_id, run_id, and capture_file are required");
        if (!session_ids.insert(fields[0]).second) row_error(number, "duplicate session_id '" + fields[0] + "'");
        const auto capture = path.parent_path() / fields[4]; if (!std::filesystem::is_regular_file(capture)) row_error(number, "capture file does not exist: " + capture.string());
        if (!util::is_sha256_hex(fields[5])) row_error(number, "capture_sha256 must be 64 hexadecimal characters");
        const double start = parse_number(fields[6], number, "start_offset_s"); const double end = parse_number(fields[7], number, "end_offset_s");
        if (start < 0.0 || end <= start) row_error(number, "time range must satisfy 0 <= start < end");
        if (fields[8] != "true" && fields[8] != "false") row_error(number, "include must be true or false");
        rows.push_back({fields[0], fields[1], fields[2], parse_state(fields[3], number), capture, fields[5], start, end, fields[8] == "true", number});
    }
    if (rows.empty()) throw std::runtime_error("manifest contains no data rows");
    return rows;
}

}  // namespace ciphertracedroid::experiments
