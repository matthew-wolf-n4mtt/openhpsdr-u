#

_CUSTOM_SUBDIRS_ = \
	hpsdr_u

_CUSTOM_EXTRA_DIST_ = \
	Custom.m4 \
	Custom.make

_CUSTOM_plugin_ldadd_ = \
	-dlopen plugins/hpsdr_u/hpsdr_u.la
