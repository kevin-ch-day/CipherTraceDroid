#include "ciphertracedroid/experiments/session_manifest.hpp"
#include "ciphertracedroid/util/sha256.hpp"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <map>
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
    constexpr std::string_view header = "session_id,app_id,run_id,state,capture_file,capture_sha256,capture_source,start_offset_s,end_offset_s,include,synthetic_test_only,pilot";
    if (line != header) throw std::runtime_error("manifest header does not match required schema");
    std::vector<SessionManifestRow> rows; std::unordered_set<std::string> session_ids; std::size_t number = 1;
    while (std::getline(input, line)) {
        ++number; if (line.empty()) row_error(number, "blank rows are not allowed");
        const auto fields = split_csv(line); if (fields.size() != 12) row_error(number, "expected 12 comma-separated fields");
        if (fields[0].empty() || fields[1].empty() || fields[2].empty() || fields[4].empty()) row_error(number, "session_id, app_id, run_id, and capture_file are required");
        if (!session_ids.insert(fields[0]).second) row_error(number, "duplicate session_id '" + fields[0] + "'");
        const auto capture = path.parent_path() / fields[4]; if (!std::filesystem::is_regular_file(capture)) row_error(number, "capture file does not exist: " + capture.string());
        if (!util::is_sha256_hex(fields[5])) row_error(number, "capture_sha256 must be 64 hexadecimal characters");
        CaptureSourceKind source;
        try { source = parse_capture_source(fields[6]); }
        catch (const std::exception& error) { row_error(number, error.what()); }
        const double start = parse_number(fields[7], number, "start_offset_s"); const double end = parse_number(fields[8], number, "end_offset_s");
        if (start < 0.0 || end <= start) row_error(number, "time range must satisfy 0 <= start < end");
        for (std::size_t field : {9U, 10U, 11U}) {
            if (fields[field] != "true" && fields[field] != "false") row_error(number, "boolean fields must be true or false");
        }
        const bool synthetic = fields[10] == "true";
        if ((source == CaptureSourceKind::synthetic_fixture) != synthetic) {
            row_error(number, "synthetic_test_only must match the SyntheticFixture capture source");
        }
        rows.push_back({fields[0], fields[1], fields[2], parse_state(fields[3], number), capture,
                        fields[5], source, start, end, fields[9] == "true", synthetic,
                        fields[11] == "true", number});
    }
    if (rows.empty()) throw std::runtime_error("manifest contains no data rows");
    return rows;
}

void validate_session_manifest_integrity(const std::vector<SessionManifestRow>& rows)
{
    std::map<std::filesystem::path, std::vector<const SessionManifestRow*>> rows_by_capture;
    for (const auto& row : rows) {
        if (util::sha256_file(row.capture_file) != row.capture_sha256) {
            row_error(row.source_row, "capture SHA-256 does not match the manifest");
        }
        rows_by_capture[row.capture_file.lexically_normal()].push_back(&row);
    }
    for (auto& [capture_file, capture_rows] : rows_by_capture) {
        (void)capture_file;
        std::sort(capture_rows.begin(), capture_rows.end(),
                  [](const auto* left, const auto* right) {
                      if (left->start_offset_seconds != right->start_offset_seconds) {
                          return left->start_offset_seconds < right->start_offset_seconds;
                      }
                      return left->end_offset_seconds < right->end_offset_seconds;
                  });
        for (std::size_t index = 1; index < capture_rows.size(); ++index) {
            const auto& previous = *capture_rows[index - 1];
            const auto& current = *capture_rows[index];
            if (current.start_offset_seconds < previous.end_offset_seconds) {
                row_error(current.source_row, "time range overlaps session '" + previous.session_id + "'");
            }
        }
    }
}

}  // namespace ciphertracedroid::experiments
