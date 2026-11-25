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
add_library(cleaner_secure_core STATIC
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

target_include_directories(cleaner_secure_core PUBLIC src/core)
target_link_libraries(cleaner_secure_core PUBLIC
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
add_executable(cleaner-secure-cli src/cli/main.c)
target_link_libraries(cleaner-secure-cli PRIVATE cleaner_secure_core)
target_link_options(cleaner-secure-cli PRIVATE -Wl,--dynamicbase,--nxcompat,--high-entropy-va)

# --- GUI (Win32) ---
add_executable(cleaner-secure WIN32 src/gui/main.c)
target_link_libraries(cleaner-secure PRIVATE cleaner_secure_core comctl32)
target_link_options(cleaner-secure PRIVATE -Wl,--dynamicbase,--nxcompat,--high-entropy-va)

# --- tests ---
enable_testing()
add_executable(cleaner_secure_tests
  tests/test_main.c
  tests/test_json.c
  tests/test_ioc.c
  tests/test_response.c
)
set_target_properties(cleaner_secure_tests PROPERTIES OUTPUT_NAME cleaner-secure-tests)
target_link_libraries(cleaner_secure_tests PRIVATE cleaner_secure_core)
add_test(NAME unit COMMAND cleaner_secure_tests)

# Copy non-secret config next to binaries
foreach(target cleaner-secure-cli cleaner-secure)
  add_custom_command(TARGET ${target} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory $<TARGET_FILE_DIR:${target}>/config
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      ${CMAKE_SOURCE_DIR}/config/iocs.json $<TARGET_FILE_DIR:${target}>/config/iocs.json
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      ${CMAKE_SOURCE_DIR}/config/publishers.json $<TARGET_FILE_DIR:${target}>/config/publishers.json
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      ${CMAKE_SOURCE_DIR}/config/thresholds.json $<TARGET_FILE_DIR:${target}>/config/thresholds.json)
endforeach()
