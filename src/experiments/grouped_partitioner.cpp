#include "ciphertracedroid/experiments/grouped_partitioner.hpp"

#include <stdexcept>
#include <unordered_set>

namespace ciphertracedroid::experiments {

DatasetPartition partition_by_run(const std::vector<SampleMetadata>& samples,
                                  const std::vector<std::string>& test_run_ids)
{
    if (test_run_ids.empty()) throw std::invalid_argument("at least one held-out run is required");
    std::unordered_set<std::string> held_out(test_run_ids.begin(), test_run_ids.end());
    DatasetPartition partition;
    for (std::size_t index = 0; index < samples.size(); ++index) {
        if (samples[index].run_id.empty()) throw std::invalid_argument("sample has no run_id");
        (held_out.contains(samples[index].run_id) ? partition.test_indices : partition.training_indices).push_back(index);
    }
    if (partition.training_indices.empty() || partition.test_indices.empty()) throw std::invalid_argument("partition must contain training and test runs");
    return partition;
}

}  // namespace ciphertracedroid::experiments
