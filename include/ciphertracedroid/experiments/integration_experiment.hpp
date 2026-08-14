#pragma once

#include "ciphertracedroid/features/feature_extractor.hpp"

#include <filesystem>
#include <map>
#include <string>
#include <vector>

namespace ciphertracedroid::experiments {

enum class ExperimentCondition {
    fg_to_fg,
    fg_to_bg,
    bg_to_bg,
    bg_to_fg,
    mixed_to_fg,
    mixed_to_bg,
};

struct ExperimentSpecification {
    ExperimentCondition condition{};
    std::vector<std::string> training_states;
    std::string testing_state;
};

struct Prediction {
    ExperimentCondition condition{};
    std::string sample_id;
    std::string run_id;
    std::string actual_label;
    std::string predicted_label;
    CaptureSourceKind capture_source{CaptureSourceKind::synthetic_fixture};
};

struct ClassMetrics {
    std::string label;
    double precision{};
    double recall{};
    double f1{};
    std::size_t support{};
};

struct MetricsReport {
    double accuracy{};
    double macro_precision{};
    double macro_recall{};
    double macro_f1{};
    std::vector<std::string> labels;
    std::vector<std::vector<std::size_t>> confusion_matrix;
    std::vector<ClassMetrics> per_class;
};

class NearestCentroidClassifier {
public:
    void train(const std::vector<const features::DatasetSample*>& samples);
    [[nodiscard]] std::string predict(const features::FeatureVector& predictors) const;
    [[nodiscard]] bool trained() const noexcept { return !centroids_.empty(); }

private:
    std::map<std::string, std::vector<double>> centroids_;
};

struct ConditionResult {
    ExperimentSpecification specification;
    std::vector<std::string> training_run_ids;
    std::vector<std::string> test_run_ids;
    std::vector<Prediction> predictions;
    MetricsReport metrics;
};

struct ExperimentResult {
    std::vector<features::DatasetSample> samples;
    std::vector<ConditionResult> conditions;
};

[[nodiscard]] std::string to_string(ExperimentCondition condition);
[[nodiscard]] std::vector<ExperimentSpecification> six_condition_specifications();
[[nodiscard]] MetricsReport calculate_metrics(const std::vector<std::string>& actual,
                                              const std::vector<std::string>& predicted);
void validate_no_run_leakage(const std::vector<std::string>& training_run_ids,
                             const std::vector<std::string>& test_run_ids);
void validate_capture_sources(const std::vector<features::DatasetSample>& samples,
                              bool routed_primary_experiment,
                              bool publication_requested,
                              bool require_routed_timing);
[[nodiscard]] ExperimentResult run_synthetic_six_condition_experiment();
[[nodiscard]] ExperimentResult run_six_condition_experiment(
    std::vector<features::DatasetSample> samples, bool routed_primary_experiment);
[[nodiscard]] std::filesystem::path write_synthetic_evidence_bundle(
    const ExperimentResult& result, const std::filesystem::path& output_root,
    const std::string& experiment_id);

}  // namespace ciphertracedroid::experiments
