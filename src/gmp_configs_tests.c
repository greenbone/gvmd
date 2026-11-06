/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gmp_configs.c"

#include <cgreen/cgreen.h>

Describe (gmp_configs);
BeforeEach (gmp_configs) {}
AfterEach (gmp_configs) {}

preference_t *
__wrap_get_nvt_preference_by_id (const char *nvt_oid, const char *find_id,
                                 const char *check_name, const char *check_type,
                                 const char *value)
{
  return preference_new (NULL, NULL, NULL, NULL, NULL, NULL,
                         NULL, NULL, NULL, 0);
}

Ensure (gmp_configs, parse_config_entity_frees_import_alts_for_nvt_preference)
{
  entity_t config;
  const char *xml =
    "<config>"
    "  <name>config</name>"
    "  <preferences>"
    "    <preference>"
    "      <nvt oid=\"1.3.6.1.4.1.25623.1.0.100315\">"
    "        <name>nvt</name>"
    "      </nvt>"
    "      <id>1</id>"
    "      <name>preference one</name>"
    "      <type>entry</type>"
    "      <value>one</value>"
    "      <alt>a</alt>"
    "    </preference>"
    "    <preference>"
    "      <nvt oid=\"1.3.6.1.4.1.25623.1.0.100315\">"
    "        <name>nvt</name>"
    "      </nvt>"
    "      <id>2</id>"
    "      <name>preference two</name>"
    "      <type>entry</type>"
    "      <value>two</value>"
    "      <alt>b</alt>"
    "    </preference>"
    "  </preferences>"
    "</config>";
  int index;

  assert_that (parse_entity (xml, &config), is_equal_to (0));

  for (index = 0; index < 4; index++)
    {
      char *name, *comment;
      int all_selector;
      array_t *selectors, *preferences;

      assert_that (parse_config_entity (config, NULL, &name, &comment, NULL,
                                        &all_selector, &selectors,
                                        &preferences, NULL),
                   is_equal_to (0));

      cleanup_import_preferences (preferences);
      array_free (selectors);
    }

  free_entity (config);
}

Ensure (gmp_configs, parse_config_entity_frees_import_alts_without_pref_id)
{
  entity_t config;
  const char *xml =
    "<config>"
    "  <name>config</name>"
    "  <preferences>"
    "    <preference>"
    "      <nvt oid=\"1.3.6.1.4.1.25623.1.0.100315\">"
    "        <name>nvt</name>"
    "      </nvt>"
    "      <name>preference</name>"
    "      <type>entry</type>"
    "      <value>value</value>"
    "      <alt>a</alt>"
    "    </preference>"
    "  </preferences>"
    "</config>";
  int index;

  assert_that (parse_entity (xml, &config), is_equal_to (0));

  for (index = 0; index < 8; index++)
    {
      char *name, *comment;
      int all_selector;
      array_t *selectors, *preferences;

      assert_that (parse_config_entity (config, NULL, &name, &comment, NULL,
                                        &all_selector, &selectors,
                                        &preferences, NULL),
                   is_equal_to (-1));
    }

  free_entity (config);
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, gmp_configs,
                         parse_config_entity_frees_import_alts_for_nvt_preference);
  add_test_with_context (suite, gmp_configs,
                         parse_config_entity_frees_import_alts_without_pref_id);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
