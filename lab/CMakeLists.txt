cmake_minimum_required(VERSION 3.16)
project(sims3_synthetic_memory_lab LANGUAGES CXX)

if(APPLE)
    set(CMAKE_OSX_ARCHITECTURES "arm64" CACHE STRING "Build the research lab for Apple silicon" FORCE)
endif()

add_executable(synthetic_memory_lab src/main.cpp)
target_compile_features(synthetic_memory_lab PRIVATE cxx_std_17)
set_target_properties(synthetic_memory_lab PROPERTIES CXX_EXTENSIONS OFF)

include(CTest)
if(BUILD_TESTING)
    add_test(NAME synthetic_memory_checks COMMAND synthetic_memory_lab)
endif()
