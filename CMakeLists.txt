cmake_minimum_required(VERSION 3.20)

project(SlipNet
    VERSION 0.1.0
    DESCRIPTION "Network Intelligence CLI"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include_directories(include)

file(GLOB_RECURSE SOURCES
    CONFIGURE_DEPENDS
    src/*.cpp
)

add_executable(slipnet ${SOURCES})

if(UNIX)
    target_link_libraries(slipnet PRIVATE pthread)
endif()