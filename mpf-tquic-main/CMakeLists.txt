# Copyright (c) 2025 Chemnitz University of Technology
# Author: André Apitzsch
#
# SPDX-License-Identifier: AGPL-3.0-or-later

cmake_minimum_required(VERSION 3.18)

project(mpf-tquic
        VERSION 0.0.1
        DESCRIPTION "Multipath Function Gateway (using tquic)"
        LANGUAGES C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(libtquic STATIC IMPORTED)

find_library(TQUIC_LIB NAMES tquic libtquic.a)
if (TQUIC_LIB)
    set_property(TARGET libtquic PROPERTY IMPORTED_LOCATION ${TQUIC_LIB})
    find_path(TQUIC_INC NAMES tquic.h)
    target_include_directories(libtquic INTERFACE ${TQUIC_INC})
else()
    include(ExternalProject)
    set(tquic_path "target/release/libtquic.so")
    ExternalProject_Add(tquic
        GIT_REPOSITORY  https://github.com/Tencent/tquic.git
        GIT_TAG         "origin/develop"
        BUILD_IN_SOURCE TRUE
        CONFIGURE_COMMAND ""
        BUILD_COMMAND cargo build --release -F ffi
        INSTALL_COMMAND ""
        BYPRODUCTS "<SOURCE_DIR>/${tquic_path}"
    )
    ExternalProject_Get_Property(tquic SOURCE_DIR)
    file(MAKE_DIRECTORY ${SOURCE_DIR}/include)
    set_property(TARGET libtquic PROPERTY IMPORTED_LOCATION ${SOURCE_DIR}/${tquic_path})
    target_include_directories(libtquic INTERFACE ${SOURCE_DIR}/include)
    add_dependencies(libtquic tquic)
endif()

find_library(EV_LIB NAMES ev)
find_path(EV_INC NAMES ev.h)
include_directories(${EV_INC})

# needed if static tquic library is used
find_library(M_LIB m)

add_executable(mpf-gw-client src/mpf-client.c)
target_link_libraries(mpf-gw-client PRIVATE libtquic ${EV_LIB} ${M_LIB})

add_executable(mpf-gw-server src/mpf-server.c)
target_link_libraries(mpf-gw-server PRIVATE libtquic ${EV_LIB} ${M_LIB})
