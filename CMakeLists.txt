cmake_minimum_required(VERSION 3.16)

project(ChaCha20-Blake2s-SIV C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -O3)
endif()

set(
    SIV_SOURCES
    src/cc20_b2s_siv.c
    lib/blake2s.c
    lib/memzero.c
)

add_library(cc20_b2s_siv_128 STATIC ${SIV_SOURCES})
target_compile_definitions(cc20_b2s_siv_128 PUBLIC CC20_B2S_SIV_128)
target_include_directories(cc20_b2s_siv_128 PUBLIC include PRIVATE lib)

add_library(cc20_b2s_siv_256 STATIC ${SIV_SOURCES})
target_compile_definitions(cc20_b2s_siv_256 PUBLIC CC20_B2S_SIV_256)
target_include_directories(cc20_b2s_siv_256 PUBLIC include PRIVATE lib)

add_executable(functional_128 test/functional.c)
target_link_libraries(functional_128 PRIVATE cc20_b2s_siv_128)

add_executable(functional_256 test/functional.c)
target_link_libraries(functional_256 PRIVATE cc20_b2s_siv_256)

add_executable(benchmark_128 test/benchmark.c)
target_link_libraries(benchmark_128 PRIVATE cc20_b2s_siv_128)

add_executable(benchmark_256 test/benchmark.c)
target_link_libraries(benchmark_256 PRIVATE cc20_b2s_siv_256)

add_executable(example example/example.c)
target_link_libraries(example PRIVATE cc20_b2s_siv_256)

add_custom_target(
    run_example
    COMMAND $<TARGET_FILE:example>
    DEPENDS example
    USES_TERMINAL
)

enable_testing()
add_test(NAME functional_128 COMMAND functional_128)
add_test(NAME functional_256 COMMAND functional_256)
