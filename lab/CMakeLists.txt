cmake_minimum_required(VERSION 3.16)
project(sims3_x86_subset_lab LANGUAGES CXX)

if(APPLE)
    set(CMAKE_OSX_ARCHITECTURES "arm64" CACHE STRING "Build the research lab for Apple silicon" FORCE)
endif()

add_library(x86_subset_core src/x86_subset.cpp)
target_include_directories(x86_subset_core PUBLIC include)
target_compile_features(x86_subset_core PUBLIC cxx_std_17)
set_target_properties(x86_subset_core PROPERTIES CXX_EXTENSIONS OFF)

add_executable(x86_subset_lab src/x86_subset_lab.cpp)
target_link_libraries(x86_subset_lab PRIVATE x86_subset_core)
target_compile_features(x86_subset_lab PRIVATE cxx_std_17)
set_target_properties(x86_subset_lab PROPERTIES CXX_EXTENSIONS OFF)

add_executable(memory_boundary_tests tests/memory_boundary_tests.cpp)
target_include_directories(memory_boundary_tests PRIVATE include)
target_compile_features(memory_boundary_tests PRIVATE cxx_std_17)
set_target_properties(memory_boundary_tests PROPERTIES CXX_EXTENSIONS OFF)

add_executable(x86_subset_tests tests/x86_subset_tests.cpp)
target_link_libraries(x86_subset_tests PRIVATE x86_subset_core)
target_compile_features(x86_subset_tests PRIVATE cxx_std_17)
set_target_properties(x86_subset_tests PROPERTIES CXX_EXTENSIONS OFF)

include(CTest)
if(BUILD_TESTING)
    add_test(NAME marco0_memory_checks COMMAND memory_boundary_tests)
    add_test(NAME x86_subset_checks COMMAND x86_subset_tests)
    add_test(NAME x86_subset_cli_default COMMAND x86_subset_lab)
    add_test(NAME x86_subset_cli_all COMMAND x86_subset_lab --program all --max-steps 10000)
endif()
