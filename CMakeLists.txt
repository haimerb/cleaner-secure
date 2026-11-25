cmake_minimum_required(VERSION 3.20)
project(cleaner-secure C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

add_compile_options(-Wall -Wextra -fstack-protector-strong -Wformat=2 -Werror=format-security)
add_compile_definitions(_FORTIFY_SOURCE=2)

# --- core static library ---
add_library(cleaner_core STATIC
  src/core/proc.c
  src/core/metrics.c
  src/core/config.c
  src/core/json.c
  src/core/ioc.c
  src/core/trust.c
  src/core/virustotal.c
  src/core/registry_scan.c
  src/core/eventlog_scan.c
  src/core/detect.c
  src/core/response.c
)

target_include_directories(cleaner_core PUBLIC src/core)
target_link_libraries(cleaner_core PUBLIC
  advapi32
  wevtapi
  crypt32
  wintrust
  bcrypt
  ws2_32
  winhttp
  ole32
  shell32
  version
  psapi
)

# --- CLI ---
add_executable(cleaner-c-cli src/cli/main.c)
target_link_libraries(cleaner-c-cli PRIVATE cleaner_core)
target_link_options(cleaner-c-cli PRIVATE -Wl,--dynamicbase,--nxcompat,--high-entropy-va)

# --- GUI (Win32) ---
add_executable(cleaner-c WIN32 src/gui/main.c)
target_link_libraries(cleaner-c PRIVATE cleaner_core comctl32)
target_link_options(cleaner-c PRIVATE -Wl,--dynamicbase,--nxcompat,--high-entropy-va)

# --- tests ---
enable_testing()
add_executable(cleaner_tests
  tests/test_main.c
  tests/test_json.c
  tests/test_ioc.c
  tests/test_response.c
)
target_link_libraries(cleaner_tests PRIVATE cleaner_core)
add_test(NAME unit COMMAND cleaner_tests)

# Copy non-secret config next to binaries
foreach(target cleaner-c-cli cleaner-c)
  add_custom_command(TARGET ${target} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory $<TARGET_FILE_DIR:${target}>/config
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      ${CMAKE_SOURCE_DIR}/config/iocs.json $<TARGET_FILE_DIR:${target}>/config/iocs.json
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      ${CMAKE_SOURCE_DIR}/config/publishers.json $<TARGET_FILE_DIR:${target}>/config/publishers.json
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      ${CMAKE_SOURCE_DIR}/config/thresholds.json $<TARGET_FILE_DIR:${target}>/config/thresholds.json)
endforeach()
