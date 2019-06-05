/* Copyright (C) 2019 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "manage.c"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

/* truncate_certificate */

static void
truncate_certificate_given_truncated (void **state)
{
  const gchar *given;
  gchar *truncated;

  given = "-----BEGIN CERTIFICATE-----\n"
          "MIIEjTCCAvWgAwIBAgIMWtd9bxgrX+9SgEHXMA0GCSqGSIb3DQEBCwUAMGIxKjAo\n"
          "BgNVBAsTIUNlcnRpZmljYXRlIEF1dGhvcml0eSBmb3IgYy5sb2NhbDESMBAGA1UE\n"
          "ChMJR1ZNIFVzZXJzMRMwEQYDVQQHEwpPc25hYnJ1ZWNrMQswCQYDVQQGEwJERTAe\n"
          "Fw0xODA0MTgxNzE2MzFaFw0yODA0MTcxNzE2MzFaMGIxKjAoBgNVBAsTIUNlcnRp\n"
          "ZmljYXRlIEF1dGhvcml0eSBmb3IgYy5sb2NhbDESMBAGA1UEChMJR1ZNIFVzZXJz\n"
          "MRMwEQYDVQQHEwpPc25hYnJ1ZWNrMQswCQYDVQQGEwJERTCCAaIwDQYJKoZIhvcN\n"
          "AQEBBQADggGPADCCAYoCggGBAN7Xjg8ZUAVg3URxV8DJ7DhArjEzR7m1BKYC3PPu\n"
          "yaAnRZqed4eZo9t6Gk+EvZxjkyN79Sooz9xpYV43naBLzTJlgbTIhkKDi9t9kB9O\n"
          "5kA8b5YxKDHaVmmJ1oxR3k115fLtBcwyjt6juL4FvyP+zJ7v1bLcXSjgUytuAce1\n"
          "C2BTLP8IaLde1bkhxINnD6moEarsZex0THQffPof6nI1gaPiDOXorzWCTegMnT1s\n"
          "26jRvQog8H7Tw+TvGwENW28MwrTy5ZnzwWIND64vmPy3oC5LQhTacd++84CstuZ9\n"
          "nI4mXh++gXRqP7lx9CSpVH+z7/Lo9S3JkWvl756m1ieJtX6bJtAadDdOsofbgasN\n"
          "xhJ42oxjjxdYdH5s0AX2frv+OvnBIWCGN9/6Tws1VCAF1SjIB7GRuyM7FcUoONtx\n"
          "svQiwNal/hOCN6DbCSM/ff76G4VwKOUlpY3GJdveTugum7V7VN9hYBSBcK45diAd\n"
          "b0ZZiRSq9T61/zFayeVQWPiWfwIDAQABo0MwQTAPBgNVHRMBAf8EBTADAQH/MA8G\n"
          "A1UdDwEB/wQFAwMHBgAwHQYDVR0OBBYEFBHD0+uQ+JXQmoUvLIJGldpGgaUdMA0G\n"
          "CSqGSIb3DQEBCwUAA4IBgQCqW2XCz2zMW14oKUu0jq33MKUE0MKG2VUy/JjVyUl9\n"
          "Vg2ZIuDFnX3qpGZJaHDOeFz3xYGcLny0QuKm4I+zYL6/rmDMhcHyuO3N+cOc+x4X\n"
          "4PRz8jydhrOMED16Tg0+o5L3JDplWpmsqUKu+sY378ZNdGPBIE1LIIzOjH296SWe\n"
          "0fztTTHLr56ftmakwC241Etmgf8ow95kxhFxbxB0hUFcIkCvi0S9eZ4ip0v/Yo2z\n"
          "lZ/DYl9GnkdnwlHB/f1/iZzrn7arEKwhqE8L/STJH+K0nJT4IGQZnyUfId7Jb+lO\n"
          "HWIyYyrUHkqIRqfybZrDXPTYGW/NvheOm8OTQmz65ySLWWNVpy2TRoLD3198GSF9\n"
          "fnkIVNvsMB5h5uCzboV+HqkYX72wg1Vfda0/8M/riYbEaxNcKKfuReoPNoCOBC8h\n"
          "NKOM6mBOCkc7MifVDVwCxaVlvGX5fKzHDhfSoNreotdL2mFJfk15Jjk4w3bmgiVT\n"
          "u1UuTizi5guqzOf+57s4o7Q=\n"
          "-----END CERTIFICATE-----\n";

  truncated = truncate_certificate (given);
  assert_string_equal (truncated, given);
  g_free (truncated);
}

/* delete_reports */

// TODO
//
// To test this kind of function we need to isolate the code in the manage.c
// module.  So we need to create stubs/mocks in manage_tests.c that simulate
// init_report_iterator, next_report, delete_report_internal and
// cleanup_iterator.  Then we can use these stubs/mocks to create simple
// tests of delete_reports, like delete_reports_deletes_each_report_once or
// delete_reports_returns_negative_1_on_error.
//
// Should be easier to do after splitting Manager source code up.

/* Test suite. */

int
main (int argc, char **argv)
{
  const struct CMUnitTest tests[] = { cmocka_unit_test (truncate_certificate_given_truncated) };

  return cmocka_run_group_tests (tests, NULL, NULL);
}
