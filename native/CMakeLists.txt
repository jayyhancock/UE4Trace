cmake_minimum_required(VERSION 3.22)
project(UE4Trace VERSION 0.1.0 LANGUAGES C CXX ASM)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
if(NOT ANDROID OR NOT ANDROID_ABI STREQUAL "arm64-v8a")
  message(FATAL_ERROR "The native observer targets Android arm64-v8a")
endif()

include(FetchContent)
if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()
set(UE4TRACE_DOBBY_COMMIT "b0176de574104726bb68dff3b77ee666300fc338")
set(UE4TRACE_JSON_COMMIT "55f93686c01528224f448c19128836e7df245f72")
set(DOBBY_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
set(DOBBY_BUILD_TEST OFF CACHE BOOL "" FORCE)
set(DOBBY_DEBUG OFF CACHE BOOL "" FORCE)
set(Plugin.SymbolResolver OFF CACHE BOOL "" FORCE)
set(Plugin.ImportTableReplace OFF CACHE BOOL "" FORCE)
set(Plugin.Android.BionicLinkerUtil OFF CACHE BOOL "" FORCE)
set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
set(JSON_Install OFF CACHE BOOL "" FORCE)
FetchContent_Declare(dobby
  URL "https://codeload.github.com/jmpews/Dobby/tar.gz/${UE4TRACE_DOBBY_COMMIT}"
  URL_HASH SHA256=0e6ca036418718732a98b136262bd0e50bf8c5b29cbef579965abc8231d252e8)
FetchContent_Declare(nlohmann_json
  URL "https://codeload.github.com/nlohmann/json/tar.gz/${UE4TRACE_JSON_COMMIT}"
  URL_HASH SHA256=67f4cdd9ca930c9c1e130af4a437c7fc98fab77a2846fc2d2a14b4943831f8ef)
FetchContent_MakeAvailable(dobby nlohmann_json)

set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS src/ProcessEventTracer.cpp src/ProcessEventTracer.h)
file(SHA256 "${CMAKE_CURRENT_SOURCE_DIR}/src/ProcessEventTracer.cpp" UE4TRACE_CPP_SHA)
file(SHA256 "${CMAKE_CURRENT_SOURCE_DIR}/src/ProcessEventTracer.h" UE4TRACE_HEADER_SHA)
file(SHA256 "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt" UE4TRACE_CMAKE_SHA)
string(SHA256 UE4TRACE_BUILD_SHA "public-0.1.0;${UE4TRACE_CPP_SHA};${UE4TRACE_HEADER_SHA};${UE4TRACE_CMAKE_SHA};${UE4TRACE_DOBBY_COMMIT};${UE4TRACE_JSON_COMMIT};${CMAKE_CXX_COMPILER_VERSION};arm64-v8a;c++_static")
file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/artifacts/native-manifest.json"
  CONTENT "{\"agent_version\":\"0.1.0\",\"agent_build\":\"${UE4TRACE_BUILD_SHA}\",\"protocol\":1,\"dobby_commit\":\"${UE4TRACE_DOBBY_COMMIT}\",\"json_commit\":\"${UE4TRACE_JSON_COMMIT}\"}\n")

add_library(ue4trace SHARED src/ProcessEventTracer.cpp)
target_compile_definitions(ue4trace PRIVATE UE4TRACE_BUILD_SHA="${UE4TRACE_BUILD_SHA}" UE4TRACE_AGENT_VERSION="0.1.0")
target_link_libraries(ue4trace PRIVATE dobby_static nlohmann_json::nlohmann_json log dl)
target_compile_options(ue4trace PRIVATE -Wall -Wextra -Wpedantic -fvisibility=hidden -fno-omit-frame-pointer)
target_link_options(ue4trace PRIVATE -Wl,--build-id=sha1 -Wl,-z,max-page-size=16384 -Wl,--exclude-libs,ALL)

add_library(ue4trace_fixture_module SHARED tests/fixture_module.cpp)
target_link_libraries(ue4trace_fixture_module PRIVATE nlohmann_json::nlohmann_json dl)
target_link_options(ue4trace_fixture_module PRIVATE -Wl,--build-id=sha1 -Wl,-z,max-page-size=16384)
add_executable(ue4trace_fixture tests/fixture_main.cpp)
target_link_libraries(ue4trace_fixture PRIVATE ue4trace_fixture_module dl)
target_link_options(ue4trace_fixture PRIVATE -Wl,--build-id=sha1 -Wl,-z,max-page-size=16384)
file(WRITE "${CMAKE_BINARY_DIR}/fixture-rpath.rsp" "-Wl,-rpath,$ORIGIN\n")
target_link_options(ue4trace_fixture PRIVATE "@${CMAKE_BINARY_DIR}/fixture-rpath.rsp")
set_target_properties(ue4trace ue4trace_fixture ue4trace_fixture_module PROPERTIES
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/artifacts"
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/artifacts")
