# Makefile.am
# Automake file for OpenHPSDR plugin
#
# This file is part of the OpenHPSDR Plug-in for Wireshark.
# By Matthew J. Wolf <matthew.wolf.hpsdr@speciosus.net>
# Copyright 2017 Matthew J. Wolf
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

include $(top_srcdir)/Makefile.am.inc
include ../Makefile.am.inc

# the name of the plugin
PLUGIN_NAME = hpsdr_u

# Non-generated sources to be scanned for registration routines
NONGENERATED_REGISTER_C_FILES = \
	packet-hpsdr_u.c

# Non-generated sources
NONGENERATED_C_FILES = \
	$(NONGENERATED_REGISTER_C_FILES)

# Headers.
CLEAN_HEADER_FILES = \
	packet-hpsdr_u.h

HEADER_FILES = \
	$(CLEAN_HEADER_FILES)


plugin_LTLIBRARIES = hpsdr_u.la

hpsdr_u_la_SOURCES = \
	plugin.c \
	moduleinfo.h \
	$(SRC_FILES)	\
	$(HEADER_FILES)

hpsdr_u_la_CPPFLAGS = $(AM_CPPFLAGS) $(PLUGIN_CPPFLAGS)

hpsdr_u_la_CFLAGS = $(AM_CFLAGS) $(PLUGIN_CFLAGS)

hpsdr_u_la_LDFLAGS = $(PLUGIN_LDFLAGS)



CLEANFILES = \
	hpsdr_u \
	*~

MAINTAINERCLEANFILES = \
	Makefile.in	\
	plugin.c

EXTRA_DIST = \
	Makefile.common		\
	Makefile.nmake		\
	moduleinfo.nmake	\
	plugin.rc.in		\
	CMakeLists.txt
