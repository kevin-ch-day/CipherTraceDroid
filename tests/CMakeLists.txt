add_executable(ciphertracedroid_tests
    core_tests.cpp
)

target_link_libraries(ciphertracedroid_tests
    PRIVATE
        CipherTraceDroid::core
)

target_compile_features(ciphertracedroid_tests PRIVATE cxx_std_20)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(ciphertracedroid_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(NAME core_contracts COMMAND ciphertracedroid_tests)
add_test(NAME cli_default COMMAND ciphertracedroid)
add_test(NAME cli_help COMMAND ciphertracedroid --help)
add_test(NAME cli_version COMMAND ciphertracedroid --version)
add_test(NAME cli_info COMMAND ciphertracedroid info)
add_test(NAME cli_unknown COMMAND ciphertracedroid invalid-command)
set_tests_properties(cli_unknown PROPERTIES WILL_FAIL TRUE)
add_test(NAME cli_inspect_malformed COMMAND ciphertracedroid inspect)
set_tests_properties(cli_inspect_malformed PROPERTIES WILL_FAIL TRUE)
add_test(NAME cli_inspect_missing_file COMMAND ciphertracedroid inspect missing.pcap)
set_tests_properties(cli_inspect_missing_file PROPERTIES WILL_FAIL TRUE)
