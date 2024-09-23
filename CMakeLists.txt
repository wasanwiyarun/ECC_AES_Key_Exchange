# Minimum version of CMake required
cmake_minimum_required(VERSION 3.10)

# Project name and version
project(EccAesKeyExchange VERSION 1.0)

# Set the C standard to C11 (optional, you can adjust if needed)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)
set(OPENSSL_ROOT_DIR "/usr/lib/ssl")
set(OPENSSL_INCLUDE_DIR "/usr/include/openssl")

# Find the OpenSSL package
find_package(OpenSSL REQUIRED)

# Add the executable target
add_executable(EccAesKeyExchange main.c)

# Link the OpenSSL libraries to your target
target_link_libraries(EccAesKeyExchange OpenSSL::Crypto)
