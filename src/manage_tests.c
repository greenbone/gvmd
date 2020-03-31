/* Copyright (C) 2019 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "manage.c"

#include <cgreen/cgreen.h>

Describe (manage);
BeforeEach (manage) {}
AfterEach (manage) {}

/* truncate_certificate */

Ensure (manage, truncate_certificate_given_truncated)
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
  assert_that (truncated, is_equal_to_string (given));
  g_free (truncated);
}

/* truncate_text */

Ensure (manage, truncate_text_truncates)
{
  gchar *given;

  given = g_strdup ("1234567890");

  truncate_text (given, 4, 0 /* Not XML. */, NULL /* No suffix. */);
  assert_that (given, is_equal_to_string ("1234"));
  g_free (given);
}

Ensure (manage, truncate_text_does_not_truncate)
{
  const gchar *original;
  gchar *given;

  original = "1234567890";
  given = g_strdup (original);
  truncate_text (given, 40, 0 /* Not XML. */, NULL /* No suffix. */);
  assert_that (given, is_equal_to_string (original));
  g_free (given);
}

Ensure (manage, truncate_text_handles_null)
{
  truncate_text (NULL, 40, 0 /* Not XML. */, NULL /* No suffix. */);
}

Ensure (manage, truncate_text_appends_suffix)
{
  const gchar *suffix;
  gchar *given;

  suffix = "abc";
  given = g_strdup ("1234567890");

  truncate_text (given, strlen (suffix) + 1, 0 /* Not XML. */, suffix);
  assert_that (given, is_equal_to_string ("1abc"));
  g_free (given);
}

Ensure (manage, truncate_text_skips_suffix)
{
  const gchar *suffix;
  gchar *given;

  suffix = "abc";
  given = g_strdup ("1234567890");

  truncate_text (given,
                 /* Too little space for suffix. */
                 strlen (suffix) - 1,
                 /* Not XML. */
                 0,
                 suffix);
  assert_that (given, is_equal_to_string ("12"));
  g_free (given);
}

Ensure (manage, truncate_text_preserves_xml)
{
  gchar *given;

  given = g_strdup ("12&nbsp;90");

  truncate_text (given, 5, 1 /* Preserve entities. */, NULL /* No suffix. */);
  assert_that (given, is_equal_to_string ("12"));
  g_free (given);
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
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, manage, truncate_certificate_given_truncated);

  add_test_with_context (suite, manage, truncate_text_truncates);
  add_test_with_context (suite, manage, truncate_text_does_not_truncate);
  add_test_with_context (suite, manage, truncate_text_handles_null);
  add_test_with_context (suite, manage, truncate_text_appends_suffix);
  add_test_with_context (suite, manage, truncate_text_skips_suffix);
  add_test_with_context (suite, manage, truncate_text_preserves_xml);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
