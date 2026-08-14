#include "ciphertracedroid/experiments/integration_experiment.hpp"

#include "ciphertracedroid/util/sha256.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <sys/wait.h>
#include <unistd.h>

namespace ciphertracedroid::experiments {
namespace {

std::vector<std::string> sorted_unique(std::vector<std::string> values)
{
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
    return values;
}

std::string json_escape(const std::string& value)
{
    std::ostringstream output;
    output << '\"';
    for (char character : value) {
        if (character == '\"' || character == '\\') output << '\\' << character;
        else if (character == '\n') output << "\\n";
        else output << character;
    }
    output << '\"';
    return output.str();
}

std::string utc_timestamp()
{
    const auto now = std::chrono::system_clock::now();
    const std::time_t time = std::chrono::system_clock::to_time_t(now);
    std::tm utc{};
    gmtime_r(&time, &utc);
    std::ostringstream output;
    output << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    return output.str();
}

std::string run_process(const std::vector<std::string>& arguments)
{
    int descriptors[2]{};
    if (pipe(descriptors) != 0) throw std::runtime_error("could not create provenance pipe");
    const pid_t process = fork();
    if (process < 0) {
        close(descriptors[0]);
        close(descriptors[1]);
        throw std::runtime_error("could not start provenance command");
    }
    if (process == 0) {
        dup2(descriptors[1], STDOUT_FILENO);
        dup2(descriptors[1], STDERR_FILENO);
        close(descriptors[0]);
        close(descriptors[1]);
        std::vector<char*> raw;
        raw.reserve(arguments.size() + 1);
        for (const auto& argument : arguments) raw.push_back(const_cast<char*>(argument.c_str()));
        raw.push_back(nullptr);
        execvp(raw.front(), raw.data());
        _exit(127);
    }
    close(descriptors[1]);
    std::string output;
    std::array<char, 4096> buffer{};
    ssize_t count = 0;
    while ((count = read(descriptors[0], buffer.data(), buffer.size())) > 0) {
        output.append(buffer.data(), static_cast<std::size_t>(count));
    }
    close(descriptors[0]);
    int status = 0;
    waitpid(process, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        throw std::runtime_error("could not collect repository provenance");
    }
    while (!output.empty() && (output.back() == '\n' || output.back() == '\r')) output.pop_back();
    return output;
}

std::string fedora_description()
{
    std::ifstream input("/etc/fedora-release");
    std::string value;
    std::getline(input, value);
    return value.empty() ? "unknown Fedora release" : value;
}

void write_text(const std::filesystem::path& path, const std::string& text)
{
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("could not create evidence artifact: " + path.string());
    output << text;
    if (!output) throw std::runtime_error("could not write evidence artifact: " + path.string());
}

features::FeatureVector synthetic_vector(int app, int run, bool foreground, int sample)
{
    features::FeatureVector vector;
    const double app_base = 18.0 + static_cast<double>(app) * 13.0;
    const double state_delta = foreground ? 9.0 : -3.0;
    const double run_delta = static_cast<double>(run) * 0.7;
    const double sample_delta = static_cast<double>(sample) * 0.25;
    vector.packet_count = app_base + state_delta + run_delta + sample_delta;
    vector.total_ip_bytes = vector.packet_count * (220.0 + app * 90.0 + (foreground ? 30.0 : 0.0));
    vector.packets_per_second = vector.packet_count / 5.0;
    vector.ip_bytes_per_second = vector.total_ip_bytes / 5.0;
    vector.ip_size_mean = vector.total_ip_bytes / vector.packet_count;
    vector.ip_size_stddev = 20.0 + app * 4.0 + sample;
    vector.ip_size_min = 60.0;
    vector.ip_size_max = vector.ip_size_mean + 180.0;
    vector.ip_size_median = vector.ip_size_mean - 5.0;
    vector.ip_size_q1 = vector.ip_size_mean - 35.0;
    vector.ip_size_q3 = vector.ip_size_mean + 40.0;
    vector.outbound_packet_fraction = 0.38 + app * 0.06 + (foreground ? 0.04 : 0.0);
    vector.inbound_packet_fraction = 0.95 - vector.outbound_packet_fraction;
    vector.unknown_packet_fraction = 0.05;
    vector.outbound_packet_count = vector.packet_count * vector.outbound_packet_fraction;
    vector.inbound_packet_count = vector.packet_count * vector.inbound_packet_fraction;
    vector.unknown_packet_count = vector.packet_count * vector.unknown_packet_fraction;
    vector.outbound_byte_fraction = vector.outbound_packet_fraction;
    vector.inbound_byte_fraction = vector.inbound_packet_fraction;
    vector.unknown_byte_fraction = vector.unknown_packet_fraction;
    vector.outbound_ip_bytes = vector.total_ip_bytes * vector.outbound_byte_fraction;
    vector.inbound_ip_bytes = vector.total_ip_bytes * vector.inbound_byte_fraction;
    vector.unknown_ip_bytes = vector.total_ip_bytes * vector.unknown_byte_fraction;
    vector.iat_mean = 5.0 / vector.packet_count;
    vector.iat_stddev = vector.iat_mean * 0.35;
    vector.iat_median = vector.iat_mean * 0.9;
    vector.iat_min = vector.iat_mean * 0.1;
    vector.iat_max = vector.iat_mean * 2.0;
    vector.tcp_packet_fraction = 0.35 + app * 0.1;
    vector.udp_packet_fraction = 0.6 - app * 0.08;
    vector.other_transport_fraction = 1.0 - vector.tcp_packet_fraction - vector.udp_packet_fraction;
    return vector;
}

std::vector<features::DatasetSample> make_synthetic_samples()
{
    std::vector<features::DatasetSample> samples;
    const std::vector<std::string> apps{"app_alpha", "app_beta", "app_gamma"};
    for (std::size_t app = 0; app < apps.size(); ++app) {
        for (int run = 1; run <= 4; ++run) {
            const std::string run_id = apps[app] + "_run" + std::to_string(run);
            for (const std::string state : {"foreground", "background", "device_control", "transition"}) {
                for (int sample = 0; sample < 2; ++sample) {
                    const bool foreground = state == "foreground";
                    auto vector = synthetic_vector(static_cast<int>(app), run, foreground, sample);
                    if (state == "device_control") {
                        vector.packet_count *= 0.25;
                        vector.total_ip_bytes *= 0.25;
                        vector.packets_per_second *= 0.25;
                        vector.ip_bytes_per_second *= 0.25;
                    } else if (state == "transition") {
                        vector.packet_count *= 1.2;
                        vector.total_ip_bytes *= 1.2;
                        vector.packets_per_second *= 1.2;
                        vector.ip_bytes_per_second *= 1.2;
                    }
                    const std::string sample_id = run_id + '_' + state + '_' + std::to_string(sample);
                    features::SampleMetadata metadata{.sample_id = sample_id,
                                                      .session_id = run_id + '_' + state,
                                                      .app_id = apps[app],
                                                      .run_id = run_id,
                                                      .activity_state = state,
                                                      .capture_source = CaptureSourceKind::synthetic_fixture,
                                                      .capture_reference = "synthetic://fixture-v1",
                                                      .window_start = sample * 5.0,
                                                      .window_end = (sample + 1) * 5.0,
                                                      .synthetic_test_only = true,
                                                      .pilot = false};
                    samples.push_back({std::move(metadata), std::move(vector)});
                }
            }
        }
    }
    return samples;
}

bool contains_state(const std::vector<std::string>& states, const std::string& state)
{
    return std::find(states.begin(), states.end(), state) != states.end();
}

void balance_mixed_training(std::vector<const features::DatasetSample*>& samples)
{
    std::map<std::tuple<std::string, std::string, std::string>,
             std::vector<const features::DatasetSample*>> groups;
    for (const auto* sample : samples) {
        groups[{sample->metadata.app_id, sample->metadata.run_id,
                sample->metadata.activity_state}].push_back(sample);
    }
    std::size_t contribution = std::numeric_limits<std::size_t>::max();
    for (const auto& [key, group] : groups) {
        (void)key;
        contribution = std::min(contribution, group.size());
    }
    std::vector<const features::DatasetSample*> balanced;
    for (const auto& [key, group] : groups) {
        (void)key;
        balanced.insert(balanced.end(), group.begin(), group.begin() +
                                                static_cast<std::ptrdiff_t>(contribution));
    }
    samples = std::move(balanced);
}

}  // namespace

std::string to_string(ExperimentCondition condition)
{
    switch (condition) {
        case ExperimentCondition::fg_to_fg: return "FG_to_FG";
        case ExperimentCondition::fg_to_bg: return "FG_to_BG";
        case ExperimentCondition::bg_to_bg: return "BG_to_BG";
        case ExperimentCondition::bg_to_fg: return "BG_to_FG";
        case ExperimentCondition::mixed_to_fg: return "Mixed_to_FG";
        case ExperimentCondition::mixed_to_bg: return "Mixed_to_BG";
    }
    throw std::logic_error("unhandled experiment condition");
}

std::vector<ExperimentSpecification> six_condition_specifications()
{
    return {{ExperimentCondition::fg_to_fg, {"foreground"}, "foreground"},
            {ExperimentCondition::fg_to_bg, {"foreground"}, "background"},
            {ExperimentCondition::bg_to_bg, {"background"}, "background"},
            {ExperimentCondition::bg_to_fg, {"background"}, "foreground"},
            {ExperimentCondition::mixed_to_fg, {"foreground", "background"}, "foreground"},
            {ExperimentCondition::mixed_to_bg, {"foreground", "background"}, "background"}};
}

void NearestCentroidClassifier::train(const std::vector<const features::DatasetSample*>& samples)
{
    if (samples.empty()) throw std::invalid_argument("classifier training set is empty");
    std::map<std::string, std::size_t> counts;
    centroids_.clear();
    for (const auto* sample : samples) {
        if (sample == nullptr || sample->metadata.app_id.empty()) throw std::invalid_argument("training sample has no label");
        const auto values = sample->predictors.values();
        auto& centroid = centroids_[sample->metadata.app_id];
        if (centroid.empty()) centroid.assign(values.size(), 0.0);
        if (centroid.size() != values.size()) throw std::invalid_argument("predictor shape mismatch");
        for (std::size_t index = 0; index < values.size(); ++index) centroid[index] += values[index];
        ++counts[sample->metadata.app_id];
    }
    for (auto& [label, centroid] : centroids_) {
        for (double& value : centroid) value /= static_cast<double>(counts.at(label));
    }
}

std::string NearestCentroidClassifier::predict(const features::FeatureVector& predictors) const
{
    if (centroids_.empty()) throw std::logic_error("classifier has not been trained");
    const auto values = predictors.values();
    std::string best_label;
    double best_distance = 0.0;
    bool first = true;
    for (const auto& [label, centroid] : centroids_) {
        if (centroid.size() != values.size()) throw std::invalid_argument("predictor shape mismatch");
        double distance = 0.0;
        for (std::size_t index = 0; index < values.size(); ++index) {
            const double difference = values[index] - centroid[index];
            distance += difference * difference;
        }
        if (first || distance < best_distance) {
            first = false;
            best_distance = distance;
            best_label = label;
        }
    }
    return best_label;
}

MetricsReport calculate_metrics(const std::vector<std::string>& actual,
                                const std::vector<std::string>& predicted)
{
    if (actual.empty() || actual.size() != predicted.size()) {
        throw std::invalid_argument("metrics require equally sized non-empty label vectors");
    }
    std::vector<std::string> labels = actual;
    labels.insert(labels.end(), predicted.begin(), predicted.end());
    labels = sorted_unique(std::move(labels));
    std::unordered_map<std::string, std::size_t> index;
    for (std::size_t position = 0; position < labels.size(); ++position) index[labels[position]] = position;
    MetricsReport report;
    report.labels = labels;
    report.confusion_matrix.assign(labels.size(), std::vector<std::size_t>(labels.size()));
    std::size_t correct = 0;
    for (std::size_t row = 0; row < actual.size(); ++row) {
        ++report.confusion_matrix[index.at(actual[row])][index.at(predicted[row])];
        if (actual[row] == predicted[row]) ++correct;
    }
    report.accuracy = static_cast<double>(correct) / static_cast<double>(actual.size());
    for (std::size_t label = 0; label < labels.size(); ++label) {
        const std::size_t tp = report.confusion_matrix[label][label];
        std::size_t predicted_total = 0;
        std::size_t actual_total = 0;
        for (std::size_t other = 0; other < labels.size(); ++other) {
            predicted_total += report.confusion_matrix[other][label];
            actual_total += report.confusion_matrix[label][other];
        }
        const double precision = predicted_total == 0 ? 0.0 : static_cast<double>(tp) / predicted_total;
        const double recall = actual_total == 0 ? 0.0 : static_cast<double>(tp) / actual_total;
        const double f1 = precision + recall == 0.0 ? 0.0 : 2.0 * precision * recall / (precision + recall);
        report.per_class.push_back({labels[label], precision, recall, f1, actual_total});
        report.macro_precision += precision;
        report.macro_recall += recall;
        report.macro_f1 += f1;
    }
    const double class_count = static_cast<double>(labels.size());
    report.macro_precision /= class_count;
    report.macro_recall /= class_count;
    report.macro_f1 /= class_count;
    return report;
}

void validate_no_run_leakage(const std::vector<std::string>& training_run_ids,
                             const std::vector<std::string>& test_run_ids)
{
    std::unordered_set<std::string> training(training_run_ids.begin(), training_run_ids.end());
    for (const auto& run : test_run_ids) {
        if (training.contains(run)) throw std::invalid_argument("run leakage detected for run_id '" + run + "'");
    }
}

void validate_capture_sources(const std::vector<features::DatasetSample>& samples,
                              bool routed_primary_experiment, bool publication_requested,
                              bool require_routed_timing)
{
    if (samples.empty()) throw std::invalid_argument("dataset is empty");
    for (const auto& sample : samples) {
        const auto source = sample.metadata.capture_source;
        if (routed_primary_experiment) require_source_for_primary_experiment(source);
        require_source_capability(source, require_routed_timing);
        if (publication_requested && !publication_primary_eligible(source)) {
            throw std::invalid_argument("publication-primary dataset contains ineligible source '" +
                                        to_string(source) + "'");
        }
        if ((source == CaptureSourceKind::synthetic_fixture) != sample.metadata.synthetic_test_only) {
            throw std::invalid_argument("synthetic source flag does not match sample provenance");
        }
    }
}

ExperimentResult run_six_condition_experiment(
    std::vector<features::DatasetSample> samples, bool routed_primary_experiment)
{
    ExperimentResult result;
    result.samples = std::move(samples);
    validate_capture_sources(result.samples, routed_primary_experiment, false,
                             routed_primary_experiment);
    std::map<std::string, std::vector<std::string>> runs_by_app;
    for (const auto& sample : result.samples) {
        runs_by_app[sample.metadata.app_id].push_back(sample.metadata.run_id);
    }
    std::unordered_set<std::string> held_out_runs;
    for (auto& [app, runs] : runs_by_app) {
        (void)app;
        runs = sorted_unique(std::move(runs));
        if (runs.size() < 2) {
            throw std::invalid_argument("each application requires at least two independent runs");
        }
        held_out_runs.insert(runs.back());
    }
    for (const auto& specification : six_condition_specifications()) {
        std::vector<const features::DatasetSample*> training;
        std::vector<const features::DatasetSample*> testing;
        std::vector<std::string> training_runs;
        std::vector<std::string> test_runs;
        for (const auto& sample : result.samples) {
            const bool held_out = held_out_runs.contains(sample.metadata.run_id);
            if (!held_out && contains_state(specification.training_states, sample.metadata.activity_state)) {
                training.push_back(&sample);
                training_runs.push_back(sample.metadata.run_id);
            }
            if (held_out && sample.metadata.activity_state == specification.testing_state) {
                testing.push_back(&sample);
                test_runs.push_back(sample.metadata.run_id);
            }
        }
        training_runs = sorted_unique(std::move(training_runs));
        test_runs = sorted_unique(std::move(test_runs));
        if (specification.training_states.size() > 1) balance_mixed_training(training);
        validate_no_run_leakage(training_runs, test_runs);
        NearestCentroidClassifier classifier;
        classifier.train(training);
        std::vector<std::string> actual;
        std::vector<std::string> predicted;
        std::vector<Prediction> predictions;
        for (const auto* sample : testing) {
            const auto prediction = classifier.predict(sample->predictors);
            actual.push_back(sample->metadata.app_id);
            predicted.push_back(prediction);
            predictions.push_back({specification.condition, sample->metadata.sample_id,
                                   sample->metadata.run_id, sample->metadata.app_id, prediction,
                                   sample->metadata.capture_source});
        }
        result.conditions.push_back({specification, training_runs, test_runs, predictions,
                                     calculate_metrics(actual, predicted)});
    }
    return result;
}

ExperimentResult run_synthetic_six_condition_experiment()
{
    return run_six_condition_experiment(make_synthetic_samples(), false);
}

std::filesystem::path write_synthetic_evidence_bundle(const ExperimentResult& result,
                                                       const std::filesystem::path& output_root,
                                                       const std::string& experiment_id)
{
    if (experiment_id.empty() || experiment_id.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != std::string::npos) {
        throw std::invalid_argument("experiment ID must contain only letters, digits, '-' or '_'");
    }
    validate_capture_sources(result.samples, false, false, false);
    const auto final_path = output_root / experiment_id;
    const auto staging_path = output_root / ("." + experiment_id + ".staging");
    if (std::filesystem::exists(final_path) || std::filesystem::exists(staging_path)) {
        throw std::runtime_error("evidence bundle already exists for experiment ID '" + experiment_id + "'");
    }
    std::filesystem::create_directories(output_root);
    std::filesystem::create_directory(staging_path);
    try {
        write_text(staging_path / "experiment.json",
                   "{\"experiment_id\":" + json_escape(experiment_id) +
                       ",\"utc_timestamp\":" + json_escape(utc_timestamp()) +
                       ",\"feature_schema_version\":1,\"window_seconds\":5,"
                       "\"transition_guard_seconds\":0,\"random_seed\":0,"
                       "\"classifier\":\"nearest_centroid_integration_baseline\","
                       "\"synthetic_test_only\":true,\"pilot\":false,"
                       "\"publication_primary_eligible\":false,"
                       "\"publication_ineligibility_reason\":\"Dataset contains SyntheticFixture capture source\"}\n");
        const auto git_head = run_process({"git", "rev-parse", "HEAD"});
        const bool git_dirty = !run_process({"git", "status", "--porcelain"}).empty();
        write_text(staging_path / "environment.json",
                   "{\"ciphertracedroid_version\":\"0.1.0\",\"git_head\":" + json_escape(git_head) +
                       ",\"git_dirty\":" + (git_dirty ? "true" : "false") +
                       ",\"platform\":" + json_escape(fedora_description()) +
                       ",\"compiler\":" + json_escape(__VERSION__) + "}\n");
        const auto capabilities = capabilities_for(CaptureSourceKind::synthetic_fixture);
        write_text(staging_path / "capture-sources.json",
                   "{\"sources\":[{\"kind\":\"synthetic_fixture\",\"whole_device_visibility\":false,"
                   "\"target_app_attribution\":false,\"routed_ip_length_fidelity\":false,"
                   "\"routed_timing_fidelity\":false,\"original_transport_semantics\":false,"
                   "\"direction_available\":" + std::string(capabilities.direction_available ? "true" : "false") +
                       ",\"publication_primary_eligible\":false}]}\n");
        std::ostringstream schema;
        schema << "{\"version\":1,\"predictors\":[";
        const auto names = features::predictor_names();
        for (std::size_t index = 0; index < names.size(); ++index) {
            if (index) schema << ',';
            schema << json_escape(names[index]);
        }
        schema << "]}\n";
        write_text(staging_path / "feature-schema.json", schema.str());
        std::ostringstream dataset;
        dataset << "capture_source,activity_state,app_id,sample_count\n";
        std::map<std::tuple<std::string, std::string, std::string>, std::size_t> counts;
        for (const auto& sample : result.samples) {
            ++counts[{to_string(sample.metadata.capture_source), sample.metadata.activity_state,
                      sample.metadata.app_id}];
        }
        for (const auto& [key, count] : counts) {
            dataset << std::get<0>(key) << ',' << std::get<1>(key) << ',' << std::get<2>(key)
                    << ',' << count << '\n';
        }
        write_text(staging_path / "dataset-summary.csv", dataset.str());
        std::ostringstream partition;
        partition << "{\"grouping_unit\":\"run_id\",\"conditions\":[";
        for (std::size_t index = 0; index < result.conditions.size(); ++index) {
            if (index) partition << ',';
            const auto& condition = result.conditions[index];
            partition << "{\"condition\":" << json_escape(to_string(condition.specification.condition))
                      << ",\"training_run_ids\":[";
            for (std::size_t run = 0; run < condition.training_run_ids.size(); ++run) {
                if (run) partition << ',';
                partition << json_escape(condition.training_run_ids[run]);
            }
            partition << "],\"test_run_ids\":[";
            for (std::size_t run = 0; run < condition.test_run_ids.size(); ++run) {
                if (run) partition << ',';
                partition << json_escape(condition.test_run_ids[run]);
            }
            partition << "]}";
        }
        partition << "]}\n";
        write_text(staging_path / "partition.json", partition.str());
        std::ostringstream predictions;
        predictions << "condition,sample_id,run_id,actual_label,predicted_label,capture_source\n";
        std::ostringstream metrics;
        metrics << "condition,scope,label,accuracy,precision,recall,f1,support\n";
        std::ostringstream matrix;
        matrix << "condition,accuracy,macro_precision,macro_recall,macro_f1\n";
        std::ostringstream confusion;
        confusion << "condition,actual_label,predicted_label,count\n";
        for (const auto& condition : result.conditions) {
            const auto name = to_string(condition.specification.condition);
            for (const auto& prediction : condition.predictions) {
                predictions << name << ',' << prediction.sample_id << ',' << prediction.run_id << ','
                            << prediction.actual_label << ',' << prediction.predicted_label << ','
                            << to_string(prediction.capture_source) << '\n';
            }
            matrix << name << ',' << condition.metrics.accuracy << ',' << condition.metrics.macro_precision
                   << ',' << condition.metrics.macro_recall << ',' << condition.metrics.macro_f1 << '\n';
            metrics << name << ",macro,ALL," << condition.metrics.accuracy << ','
                    << condition.metrics.macro_precision << ',' << condition.metrics.macro_recall << ','
                    << condition.metrics.macro_f1 << ',' << condition.predictions.size() << '\n';
            for (const auto& item : condition.metrics.per_class) {
                metrics << name << ",class," << item.label << ",," << item.precision << ','
                        << item.recall << ',' << item.f1 << ',' << item.support << '\n';
            }
            for (std::size_t actual = 0; actual < condition.metrics.labels.size(); ++actual) {
                for (std::size_t predicted = 0; predicted < condition.metrics.labels.size(); ++predicted) {
                    confusion << name << ',' << condition.metrics.labels[actual] << ','
                              << condition.metrics.labels[predicted] << ','
                              << condition.metrics.confusion_matrix[actual][predicted] << '\n';
                }
            }
        }
        write_text(staging_path / "predictions.csv", predictions.str());
        write_text(staging_path / "metrics.csv", metrics.str());
        write_text(staging_path / "confusion-matrix.csv", confusion.str());
        write_text(staging_path / "six-condition-matrix.csv", matrix.str());
        write_text(staging_path / "summary.md",
                   "# Synthetic software-validation result\n\nNOT RESEARCH EVIDENCE.\n\n"
                   "This bundle exercises the grouped six-condition experiment pipeline with synthetic fixtures.\n");
        const std::vector<std::string> artifacts{"experiment.json", "environment.json", "capture-sources.json",
                                                  "feature-schema.json", "dataset-summary.csv", "partition.json",
                                                  "predictions.csv", "metrics.csv", "confusion-matrix.csv",
                                                  "six-condition-matrix.csv", "summary.md"};
        std::ostringstream checksums;
        for (const auto& artifact : artifacts) {
            checksums << util::sha256_file(staging_path / artifact) << "  " << artifact << '\n';
        }
        write_text(staging_path / "checksums.sha256", checksums.str());
        std::filesystem::rename(staging_path, final_path);
    } catch (...) {
        std::filesystem::remove_all(staging_path);
        throw;
    }
    return final_path;
}

}  // namespace ciphertracedroid::experiments
