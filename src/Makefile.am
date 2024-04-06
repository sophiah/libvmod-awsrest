AM_CFLAGS = $(VARNISHAPI_CFLAGS) -Wall -Werror
AM_LDFLAGS = $(VARNISHAPI_LIBS) $(VMOD_LDFLAGS) -lmhash

vmod_LTLIBRARIES = libvmod_awsrestv2.la

libvmod_awsrestv2_la_SOURCES = \
	vmod_awsrestv2.c

nodist_libvmod_awsrestv2_la_SOURCES = \
	vcc_awsrestv2_if.c \
	vcc_awsrestv2_if.h

dist_man_MANS = vmod_awsrestv2.3

@BUILD_VMOD_AWSRESTV2@

AM_TESTS_ENVIRONMENT = \
	PATH="$(VMOD_TEST_PATH)" \
	LD_LIBRARY_PATH="$(VARNISH_LIBRARY_PATH)"
TEST_EXTENSIONS = .vtc
VTC_LOG_COMPILER = varnishtest -v
AM_VTC_LOG_FLAGS = -Dvmod_awsrestv2="$(VMOD_AWSRESTV2)"

TESTS = @VMOD_TESTS@

EXTRA_DIST = \
	vmod_awsrestv2.vcc \
	$(VMOD_TESTS)
