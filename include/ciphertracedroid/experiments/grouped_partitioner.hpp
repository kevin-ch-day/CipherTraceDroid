#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace ciphertracedroid::experiments {

struct SampleMetadata {
    std::string window_id;
    std::string session_id;
    std::string run_id;
    std::string app_id;
    std::string condition;
};

struct DatasetPartition {
    std::vector<std::size_t> training_indices;
    std::vector<std::size_t> test_indices;
};

[[nodiscard]] DatasetPartition partition_by_run(const std::vector<SampleMetadata>& samples,
                                                const std::vector<std::string>& test_run_ids);

}  // namespace ciphertracedroid::experiments
