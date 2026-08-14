cmake_minimum_required(VERSION 3.20)

project(
    CipherTraceDroid
    VERSION 0.1.0
    DESCRIPTION "C++ research framework for encrypted Android network traffic analysis"
    LANGUAGES CXX
)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED IMPORTED_TARGET libpcap)
find_package(OpenSSL REQUIRED)

add_library(ciphertracedroid_core STATIC
    src/analysis/condition_analysis.cpp
    src/app.cpp
    src/capture/pcap_reader.cpp
    src/device/adb_client.cpp
    src/device/android_state.cpp
    src/device/pcapdroid_controller.cpp
    src/experiments/capture_source.cpp
    src/experiments/integration_experiment.cpp
    src/experiments/manifest_builder.cpp
    src/experiments/session_manifest.cpp
    src/experiments/session_plan.cpp
    src/experiments/grouped_partitioner.cpp
    src/util/sha256.cpp
    src/util/logging.cpp
    src/features/feature_extractor.cpp
    src/features/dataset_export.cpp
    src/traffic/windowing.cpp
)

add_library(
    CipherTraceDroid::core
    ALIAS ciphertracedroid_core
)

target_include_directories(ciphertracedroid_core
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

target_compile_features(ciphertracedroid_core
    PUBLIC
        cxx_std_20
)

target_compile_definitions(ciphertracedroid_core
    PRIVATE
        CIPHERTRACEDROID_VERSION="${PROJECT_VERSION}"
)

target_link_libraries(ciphertracedroid_core PUBLIC PkgConfig::PCAP OpenSSL::Crypto)

add_executable(ciphertracedroid
    src/main.cpp
)

target_link_libraries(ciphertracedroid
    PRIVATE
        CipherTraceDroid::core
)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(ciphertracedroid_core
        PRIVATE
            -Wall
            -Wextra
            -Wpedantic
    )

    target_compile_options(ciphertracedroid
        PRIVATE
            -Wall
            -Wextra
            -Wpedantic
    )
endif()

include(CTest)

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
