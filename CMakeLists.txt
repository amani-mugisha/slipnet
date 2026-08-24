cmake_minimum_required(VERSION 3.20)

project(SlipNet
    VERSION 0.1.0
    DESCRIPTION "Network Intelligence CLI"
    LANGUAGES CXX
)

# ============================================================
# C++ STANDARD
# ============================================================

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ============================================================
# INCLUDE DIRECTORIES
# ============================================================

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# ============================================================
# DEPENDENCIES
# ============================================================

find_package(OpenSSL REQUIRED)

# ============================================================
# COMMON SOURCES
# ============================================================

file(GLOB_RECURSE COMMON_SOURCES
    CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
)

# Remove ALL platform-specific implementations.
#
# SlipNet builds ONE executable for ONE operating system.
#
# Linux build:
#     Linux implementations are added below.
#
# Windows build:
#     Windows implementations are added below.

list(FILTER COMMON_SOURCES EXCLUDE REGEX
    "/src/platform/linux/.*\\.cpp$"
)

list(FILTER COMMON_SOURCES EXCLUDE REGEX
    "/src/platform/windows/.*\\.cpp$"
)

# ============================================================
# PLATFORM-SPECIFIC SOURCES
# ============================================================

set(PLATFORM_SOURCES)

if(WIN32)

    message(STATUS "SlipNet platform: Windows")

    list(APPEND PLATFORM_SOURCES

        # Network
        "${CMAKE_CURRENT_SOURCE_DIR}/src/platform/windows/network_windows.cpp"

        # Network status
        "${CMAKE_CURRENT_SOURCE_DIR}/src/platform/windows/network_status.cpp"

        # Sockets
        "${CMAKE_CURRENT_SOURCE_DIR}/src/platform/windows/sockets_windows.cpp"

        # Connectivity
        "${CMAKE_CURRENT_SOURCE_DIR}/src/platform/windows/ping_windows.cpp"

        # TCP
        "${CMAKE_CURRENT_SOURCE_DIR}/src/platform/windows/tcp_windows.cpp"

        # Services
        "${CMAKE_CURRENT_SOURCE_DIR}/src/platform/windows/service_windows.cpp"

        # Routing
        "${CMAKE_CURRENT_SOURCE_DIR}/src/platform/windows/route_windows.cpp"

        # Topology
        "${CMAKE_CURRENT_SOURCE_DIR}/src/platform/windows/topology_windows.cpp"

        # Packet capture
        "${CMAKE_CURRENT_SOURCE_DIR}/src/platform/windows/packet_capture.cpp"


    )

elseif(UNIX)

    message(STATUS "SlipNet platform: Linux/Unix")

    list(APPEND PLATFORM_SOURCES

        # Network
        "${CMAKE_CURRENT_SOURCE_DIR}/src/platform/linux/network_linux.cpp"

        # Network status
        "${CMAKE_CURRENT_SOURCE_DIR}/src/platform/linux/network_status.cpp"

        # Sockets
        "${CMAKE_CURRENT_SOURCE_DIR}/src/platform/linux/sockets_linux.cpp"

        # Connectivity
        "${CMAKE_CURRENT_SOURCE_DIR}/src/platform/linux/ping_linux.cpp"

        # TCP
        "${CMAKE_CURRENT_SOURCE_DIR}/src/platform/linux/tcp_linux.cpp"

        # Services
        "${CMAKE_CURRENT_SOURCE_DIR}/src/platform/linux/service_linux.cpp"

        # Routing
        "${CMAKE_CURRENT_SOURCE_DIR}/src/platform/linux/route_linux.cpp"

        # Topology
        "${CMAKE_CURRENT_SOURCE_DIR}/src/platform/linux/topology_linux.cpp"

        # Packet capture
        "${CMAKE_CURRENT_SOURCE_DIR}/src/platform/linux/packet_capture.cpp"


    )

else()

    message(FATAL_ERROR
        "Unsupported operating system."
    )

endif()

# ============================================================
# EXECUTABLE
# ============================================================

add_executable(slipnet
    ${COMMON_SOURCES}
    ${PLATFORM_SOURCES}
)

# ============================================================
# OPENSSL
# ============================================================

target_link_libraries(slipnet
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
)

# ============================================================
# LINUX / UNIX
# ============================================================

if(UNIX AND NOT APPLE)

    target_link_libraries(slipnet
        PRIVATE
            pthread
    )

endif()

# ============================================================
# WINDOWS
# ============================================================

if(WIN32)

    target_link_libraries(slipnet
        PRIVATE
            ws2_32
            iphlpapi
            wpcap
            Packet
    )

endif()

# ============================================================
# BUILD INFORMATION
# ============================================================

message(STATUS "========================================")
message(STATUS "SlipNet ${PROJECT_VERSION}")
message(STATUS "Platform : ${CMAKE_SYSTEM_NAME}")
message(STATUS "Compiler : ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "C++      : C++${CMAKE_CXX_STANDARD}")
message(STATUS "========================================")