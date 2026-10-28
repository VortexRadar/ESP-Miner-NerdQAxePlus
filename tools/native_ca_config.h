/* Archived trust tests isolate trust from certificate expiry. Host only. */
#include "mbedtls/mbedtls_config.h"
#undef MBEDTLS_HAVE_TIME_DATE
