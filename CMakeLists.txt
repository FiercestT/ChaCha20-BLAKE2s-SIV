cmake_minimum_required(VERSION 3.16)

project(cbsiv C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

add_subdirectory(lib/ChaChaSlide)

enable_testing()
foreach(bits IN ITEMS 128 256)
    add_library(cbsiv_${bits} STATIC cbsiv.c)
    target_compile_definitions(cbsiv_${bits} PUBLIC CBSIV_${bits})
    target_include_directories(cbsiv_${bits} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(cbsiv_${bits} PRIVATE
        $<IF:$<CONFIG:MinSizeRel>,ccs-size,ccs-speed>
    )

    foreach(program IN ITEMS functional benchmark)
        add_executable(${program}_${bits} test/${program}.c)
        target_link_libraries(${program}_${bits} PRIVATE cbsiv_${bits})
    endforeach()
    add_test(NAME functional_${bits} COMMAND functional_${bits})
endforeach()

add_executable(example example/example.c)
target_link_libraries(example PRIVATE cbsiv_256)
add_custom_target(run_example COMMAND $<TARGET_FILE:example> DEPENDS example USES_TERMINAL)
