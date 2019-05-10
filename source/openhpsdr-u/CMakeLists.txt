# CMakeLists.txt
#
#  This file is part of the OpenHPSDR-USB Plug-in for Wireshark.
#  Matthew J. Wolf <matthew.wolf.hpsdr@speciosus.net>
#  Copyright 2019 Matthew J. Wolf
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

cmake_minimum_required(VERSION 3.1)
cmake_policy(SET CMP0048 NEW)

project(openhpsdr-u VERSION 0.3.0 DESCRIPTION "Wireshark OpenHPSDR-USB Plug-in" LANGUAGES C)

find_package(Wireshark CONFIG REQUIRED)

if(NOT Wireshark_PLUGINS_ENABLED)
	message(FATAL_ERROR "Wireshark was compiled without support for plugins")
endif()

set(CMAKE_C_VISIBILITY_PRESET hidden)
if (CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS  "-Wall -Wextra ${CMAKE_C_FLAGS}")
endif()

add_definitions(-DVERSION=\"${PROJECT_VERSION}\")

add_library(openhpsdr-u MODULE packet-openhpsdr-u.c)
set_target_properties(openhpsdr-u PROPERTIES PREFIX "" DEFINE_SYMBOL "")
target_link_libraries(openhpsdr-u epan)

install(TARGETS openhpsdr-u
	LIBRARY DESTINATION "${Wireshark_PLUGIN_INSTALL_DIR}/epan" NAMELINK_SKIP
)
