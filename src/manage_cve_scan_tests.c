/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_cve_scan.c"

#include <cgreen/cgreen.h>
#include <stdint.h>
#include <string.h>

/* An AND configuration with two OR children, as in the Firepower/FXOS
 * applicability statement. The previous report contains only the FXOS CPE. */
#define ROOT_NODE 1
#define FXOS_NODE 2
#define HARDWARE_NODE 3
#define VULNERABILITY_NODE 4

static const char *fxos_cpe = "cpe:/o:cisco:fxos:6.4.0";
static const char *hardware_cpe = "cpe:/h:cisco:firepower_1010:-";
static gboolean hardware_present;

/* Storage fixtures are separate from the in-memory evaluator fixtures. */
typedef struct
{
  long long id;
  const char *operator;
  int negate;
  const char *criteria;
  int vulnerable;
  const char *start_incl;
  const char *start_excl;
  const char *end_incl;
  const char *end_excl;
  gboolean has_criterion;
} configuration_row_t;

static const configuration_row_t default_stored_rows[] = {
  {ROOT_NODE, "AND", 0, NULL, 0, NULL, NULL, NULL, NULL, FALSE},
  {FXOS_NODE, "OR", 0, "cpe:/o:cisco:fxos:6.4.0", 0, NULL, NULL, NULL, NULL,
   TRUE},
  {FXOS_NODE, "OR", 0, "cpe:/o:cisco:fxos", 1, "7.0", "6.5", "8.0", "9.0",
   TRUE},
  {HARDWARE_NODE, "OR", 1, "cpe:/h:cisco:firepower_1010:-", 0, NULL, NULL, NULL,
   NULL, TRUE}};
static configuration_row_t stored_rows[G_N_ELEMENTS (default_stored_rows)];
static char *last_configuration_query;
static report_host_t requested_inventory_report_host;
static unsigned int configuration_query_count;
static int stored_row_count;
static int first_stored_row;
static unsigned int inventory_query_count;

void
__wrap_init_iterator (iterator_t *iterator, const char *format, ...)
{
  g_free (last_configuration_query);
  last_configuration_query = g_strdup (format);
  configuration_query_count++;
  iterator->stmt = NULL;
  iterator->done = first_stored_row;
}

gboolean
__wrap_next (iterator_t *iterator)
{
  if (iterator->stmt != NULL)
    {
      if (iterator->done >= (hardware_present ? 2 : 1))
        return FALSE;
      iterator->done++;
      return TRUE;
    }
  if (iterator->done >= stored_row_count)
    return FALSE;
  iterator->done++;
  return TRUE;
}

const char *
__wrap_iterator_string (iterator_t *iterator, int column)
{
  const configuration_row_t *row = &stored_rows[iterator->done - 1];
  switch (column)
    {
    case 1:
      return row->operator;
    case 5:
      return row->criteria;
    case 6:
      return row->start_incl;
    case 7:
      return row->start_excl;
    case 8:
      return row->end_incl;
    case 9:
      return row->end_excl;
    default:
      return NULL;
    }
}

long long int
__wrap_iterator_int64 (iterator_t *iterator, int column)
{
  (void) column;
  return stored_rows[iterator->done - 1].id;
}

int
__wrap_iterator_int (iterator_t *iterator, int column)
{
  const configuration_row_t *row = &stored_rows[iterator->done - 1];
  return column == 2 ? row->negate : row->vulnerable;
}

int
__wrap_iterator_null (iterator_t *iterator, int column)
{
  (void) column;
  return !stored_rows[iterator->done - 1].has_criterion;
}

void
__wrap_cleanup_iterator (iterator_t *iterator)
{
  (void) iterator;
}

void
__wrap_init_host_details_cpe_iterator (iterator_t *iterator,
                                       report_host_t report_host)
{
  requested_inventory_report_host = report_host;
  inventory_query_count++;
  iterator->stmt = (sql_stmt_t *) (uintptr_t) 1;
  iterator->done = 0;
}

const char *
__wrap_host_details_cpe_iterator_cpe (iterator_t *iterator)
{
  return iterator->done == 1 ? fxos_cpe : hardware_cpe;
}

static cpe_criterion_t *
test_criterion (const char *uri, gboolean vulnerable, const char *start_incl)
{
  cpe_criterion_t *criterion = g_new0 (cpe_criterion_t, 1);
  cpe_struct_init (&criterion->cpe);
  uri_cpe_to_cpe_struct (uri, &criterion->cpe);
  criterion->product = uri_cpe_to_uri_product (uri);
  criterion->vulnerable = vulnerable;
  criterion->version_start_incl = g_strdup (start_incl);
  return criterion;
}

/* Fixture builders only arrange data; evaluation and assertions stay in tests.
 * Configuration.nodes owns every node; children only borrow node pointers. */
typedef struct
{
  cpe_configuration_t *configuration;
  cpe_node_t *root;
  cpe_node_t *fxos;
  cpe_node_t *hardware;
  cpe_node_t *range;
  GPtrArray *inventory;
  cpe_host_product_t *target;
} evaluation_fixture_t;

static evaluation_fixture_t *fixture;
static cpe_configuration_t *loaded_configuration;
static GPtrArray *loaded_inventory;
static GHashTable *configuration_cache;

/**
 * @brief Arrange an application and hardware rule with application-only input.
 *
 * @return Owned fixture, released by free_evaluation_fixture.
 */
static evaluation_fixture_t *
new_evaluation_fixture (void)
{
  evaluation_fixture_t *data = g_new0 (evaluation_fixture_t, 1);
  data->configuration = g_new0 (cpe_configuration_t, 1);
  data->configuration->nodes = g_ptr_array_new_with_free_func (free_cpe_node);
  data->root = new_cpe_node (ROOT_NODE, CPE_OPERATOR_AND, FALSE);
  data->fxos = new_cpe_node (FXOS_NODE, CPE_OPERATOR_OR, FALSE);
  data->hardware = new_cpe_node (HARDWARE_NODE, CPE_OPERATOR_OR, FALSE);
  data->range = new_cpe_node (VULNERABILITY_NODE, CPE_OPERATOR_OR, FALSE);
  g_ptr_array_add (data->configuration->nodes, data->root);
  g_ptr_array_add (data->configuration->nodes, data->fxos);
  g_ptr_array_add (data->configuration->nodes, data->hardware);
  g_ptr_array_add (data->configuration->nodes, data->range);
  g_ptr_array_add (data->root->children, data->fxos);
  g_ptr_array_add (data->root->children, data->hardware);
  g_ptr_array_add (data->fxos->criteria, test_criterion (fxos_cpe, TRUE, NULL));
  g_ptr_array_add (data->hardware->criteria,
                   test_criterion (hardware_cpe, FALSE, NULL));
  g_ptr_array_add (data->range->criteria,
                   test_criterion (fxos_cpe, FALSE, NULL));
  g_ptr_array_add (data->range->criteria,
                   test_criterion ("cpe:/o:cisco:fxos", TRUE, "7.0"));
  data->configuration->root = data->root;
  data->inventory = g_ptr_array_new_with_free_func (free_cpe_host_product);
  g_ptr_array_add (data->inventory, new_cpe_host_product (fxos_cpe));
  data->target = new_cpe_host_product (fxos_cpe);
  return data;
}

/**
 * @brief Release all data owned by an evaluation fixture.
 *
 * @param[in] data  Fixture to release.
 */
static void
free_evaluation_fixture (evaluation_fixture_t *data)
{
  free_cpe_configuration (data->configuration);
  g_ptr_array_free (data->inventory, TRUE);
  free_cpe_host_product (data->target);
  g_free (data);
}

/**
 * @brief Arrange the hardware operand before the application operand.
 *
 * @param[in,out] data  Fixture whose child order is reversed.
 */
static void
arrange_hardware_first (evaluation_fixture_t *data)
{
  data->root->children->pdata[0] = data->hardware;
  data->root->children->pdata[1] = data->fxos;
}

/**
 * @brief Replace the CPE being evaluated in a fixture.
 *
 * @param[in,out] data  Fixture owning the target.
 * @param[in] uri       New target CPE URI.
 */
static void
arrange_target (evaluation_fixture_t *data, const char *uri)
{
  free_cpe_host_product (data->target);
  data->target = new_cpe_host_product (uri);
}

Describe (manage_cve_scan);
BeforeEach (manage_cve_scan)
{
  hardware_present = FALSE;
  configuration_query_count = inventory_query_count = 0;
  requested_inventory_report_host = 0;
  memcpy (stored_rows, default_stored_rows, sizeof (stored_rows));
  stored_row_count = G_N_ELEMENTS (stored_rows);
  first_stored_row = 0;
  fixture = new_evaluation_fixture ();
  loaded_configuration = NULL;
  loaded_inventory = NULL;
  configuration_cache = NULL;
  last_configuration_query = NULL;
}
AfterEach (manage_cve_scan)
{
  free_evaluation_fixture (fixture);
  free_cpe_configuration (loaded_configuration);
  if (loaded_inventory)
    g_ptr_array_free (loaded_inventory, TRUE);
  if (configuration_cache)
    g_hash_table_destroy (configuration_cache);
  g_free (last_configuration_query);
}

Ensure (manage_cve_scan, and_rule_requires_hardware_as_well_as_fxos)
{
  cpe_evaluation_t result;

  result = evaluate_cpe_configuration (
    fixture->configuration, fixture->inventory, &fixture->target->cpe);

  assert_that (result.match, is_false);
  assert_that (result.vulnerable, is_false);
  assert_that (configuration_query_count, is_equal_to (0));
}

Ensure (manage_cve_scan, and_rule_matches_when_hardware_and_fxos_are_present)
{
  cpe_evaluation_t result;
  g_ptr_array_add (fixture->inventory, new_cpe_host_product (hardware_cpe));

  result = evaluate_cpe_configuration (
    fixture->configuration, fixture->inventory, &fixture->target->cpe);

  assert_that (result.match, is_true);
  assert_that (result.vulnerable, is_true);
  assert_that (configuration_query_count, is_equal_to (0));
}

Ensure (manage_cve_scan,
        and_rule_rejects_missing_hardware_when_hardware_is_first)
{
  cpe_evaluation_t result;
  arrange_hardware_first (fixture);

  result = evaluate_cpe_configuration (
    fixture->configuration, fixture->inventory, &fixture->target->cpe);

  assert_that (result.match, is_false);
  assert_that (result.vulnerable, is_false);
  assert_that (configuration_query_count, is_equal_to (0));
}

Ensure (manage_cve_scan, out_of_range_criterion_does_not_mark_host_vulnerable)
{
  cpe_evaluation_t result;
  fixture->configuration->root = fixture->range;

  result = evaluate_cpe_configuration (
    fixture->configuration, fixture->inventory, &fixture->target->cpe);

  assert_that (result.match, is_true);
  assert_that (result.vulnerable, is_false);
  assert_that (configuration_query_count, is_equal_to (0));
}

Ensure (manage_cve_scan, and_criteria_do_not_inherit_previous_match)
{
  cpe_evaluation_t result;
  fixture->configuration->root = fixture->range;
  fixture->range->operator= CPE_OPERATOR_AND;

  result = evaluate_cpe_configuration (
    fixture->configuration, fixture->inventory, &fixture->target->cpe);

  assert_that (result.match, is_false);
  assert_that (result.vulnerable, is_false);
  assert_that (configuration_query_count, is_equal_to (0));
}

Ensure (manage_cve_scan, or_children_match_when_application_is_first)
{
  cpe_evaluation_t result;
  fixture->root->operator= CPE_OPERATOR_OR;

  result = evaluate_cpe_configuration (
    fixture->configuration, fixture->inventory, &fixture->target->cpe);

  assert_that (result.match, is_true);
  assert_that (result.vulnerable, is_true);
  assert_that (configuration_query_count, is_equal_to (0));
}

Ensure (manage_cve_scan, or_children_match_when_hardware_is_first)
{
  cpe_evaluation_t result;
  fixture->root->operator= CPE_OPERATOR_OR;
  arrange_hardware_first (fixture);

  result = evaluate_cpe_configuration (
    fixture->configuration, fixture->inventory, &fixture->target->cpe);

  assert_that (result.match, is_true);
  assert_that (result.vulnerable, is_true);
  assert_that (configuration_query_count, is_equal_to (0));
}

Ensure (manage_cve_scan, negated_and_matches_when_hardware_is_absent)
{
  cpe_evaluation_t result;
  fixture->root->negate = TRUE;

  result = evaluate_cpe_configuration (
    fixture->configuration, fixture->inventory, &fixture->target->cpe);

  assert_that (result.match, is_true);
  assert_that (result.vulnerable, is_false);
  assert_that (configuration_query_count, is_equal_to (0));
}

Ensure (manage_cve_scan, negated_and_rejects_matching_operands)
{
  cpe_evaluation_t result;
  fixture->root->negate = TRUE;
  g_ptr_array_add (fixture->inventory, new_cpe_host_product (hardware_cpe));

  result = evaluate_cpe_configuration (
    fixture->configuration, fixture->inventory, &fixture->target->cpe);

  assert_that (result.match, is_false);
  assert_that (result.vulnerable, is_false);
  assert_that (configuration_query_count, is_equal_to (0));
}

Ensure (manage_cve_scan, negated_or_rejects_matching_application)
{
  cpe_evaluation_t result;
  fixture->root->operator= CPE_OPERATOR_OR;
  fixture->root->negate = TRUE;

  result = evaluate_cpe_configuration (
    fixture->configuration, fixture->inventory, &fixture->target->cpe);

  assert_that (result.match, is_false);
  assert_that (result.vulnerable, is_false);
  assert_that (configuration_query_count, is_equal_to (0));
}

Ensure (manage_cve_scan, negated_or_rejects_matching_application_and_hardware)
{
  cpe_evaluation_t result;
  fixture->root->operator= CPE_OPERATOR_OR;
  fixture->root->negate = TRUE;
  g_ptr_array_add (fixture->inventory, new_cpe_host_product (hardware_cpe));

  result = evaluate_cpe_configuration (
    fixture->configuration, fixture->inventory, &fixture->target->cpe);

  assert_that (result.match, is_false);
  assert_that (result.vulnerable, is_false);
  assert_that (configuration_query_count, is_equal_to (0));
}

Ensure (manage_cve_scan, negated_environment_matches_when_absent)
{
  cpe_evaluation_t result;
  fixture->hardware->negate = TRUE;

  result = evaluate_cpe_configuration (
    fixture->configuration, fixture->inventory, &fixture->target->cpe);

  assert_that (result.match, is_true);
  assert_that (result.vulnerable, is_true);
  assert_that (configuration_query_count, is_equal_to (0));
}

Ensure (manage_cve_scan, negated_environment_matches_when_absent_and_first)
{
  cpe_evaluation_t result;
  fixture->hardware->negate = TRUE;
  arrange_hardware_first (fixture);

  result = evaluate_cpe_configuration (
    fixture->configuration, fixture->inventory, &fixture->target->cpe);

  assert_that (result.match, is_true);
  assert_that (result.vulnerable, is_true);
  assert_that (configuration_query_count, is_equal_to (0));
}

Ensure (manage_cve_scan, negated_environment_rejects_present_hardware)
{
  cpe_evaluation_t result;
  fixture->hardware->negate = TRUE;
  g_ptr_array_add (fixture->inventory, new_cpe_host_product (hardware_cpe));

  result = evaluate_cpe_configuration (
    fixture->configuration, fixture->inventory, &fixture->target->cpe);

  assert_that (result.match, is_false);
  assert_that (result.vulnerable, is_false);
  assert_that (configuration_query_count, is_equal_to (0));
}

Ensure (manage_cve_scan,
        negated_environment_rejects_present_hardware_when_first)
{
  cpe_evaluation_t result;
  fixture->hardware->negate = TRUE;
  arrange_hardware_first (fixture);
  g_ptr_array_add (fixture->inventory, new_cpe_host_product (hardware_cpe));

  result = evaluate_cpe_configuration (
    fixture->configuration, fixture->inventory, &fixture->target->cpe);

  assert_that (result.match, is_false);
  assert_that (result.vulnerable, is_false);
  assert_that (configuration_query_count, is_equal_to (0));
}

Ensure (manage_cve_scan, nested_negation_matches_when_hardware_is_present)
{
  cpe_evaluation_t result;
  fixture->root->negate = TRUE;
  fixture->hardware->negate = TRUE;
  g_ptr_array_add (fixture->inventory, new_cpe_host_product (hardware_cpe));

  result = evaluate_cpe_configuration (
    fixture->configuration, fixture->inventory, &fixture->target->cpe);

  assert_that (result.match, is_true);
  assert_that (result.vulnerable, is_false);
  assert_that (configuration_query_count, is_equal_to (0));
}

Ensure (manage_cve_scan, nested_negation_rejects_absent_hardware)
{
  cpe_evaluation_t result;
  fixture->root->negate = TRUE;
  fixture->hardware->negate = TRUE;

  result = evaluate_cpe_configuration (
    fixture->configuration, fixture->inventory, &fixture->target->cpe);

  assert_that (result.match, is_false);
  assert_that (result.vulnerable, is_false);
  assert_that (configuration_query_count, is_equal_to (0));
}

Ensure (manage_cve_scan,
        negated_leaf_matches_absence_without_creating_vulnerability)
{
  cpe_evaluation_t result;
  fixture->configuration->root = fixture->hardware;
  fixture->hardware->negate = TRUE;

  result = evaluate_cpe_configuration (
    fixture->configuration, fixture->inventory, &fixture->target->cpe);

  assert_that (result.match, is_true);
  assert_that (result.vulnerable, is_false);
  assert_that (configuration_query_count, is_equal_to (0));
}

Ensure (manage_cve_scan, negated_leaf_rejects_present_hardware)
{
  cpe_evaluation_t result;
  fixture->configuration->root = fixture->hardware;
  fixture->hardware->negate = TRUE;
  g_ptr_array_add (fixture->inventory, new_cpe_host_product (hardware_cpe));

  result = evaluate_cpe_configuration (
    fixture->configuration, fixture->inventory, &fixture->target->cpe);

  assert_that (result.match, is_false);
  assert_that (result.vulnerable, is_false);
  assert_that (configuration_query_count, is_equal_to (0));
}

Ensure (manage_cve_scan, negate_applies_after_and_criterion_short_circuit)
{
  cpe_evaluation_t result;
  fixture->configuration->root = fixture->range;
  fixture->range->operator= CPE_OPERATOR_AND;
  fixture->range->negate = TRUE;

  result = evaluate_cpe_configuration (
    fixture->configuration, fixture->inventory, &fixture->target->cpe);

  assert_that (result.match, is_true);
  assert_that (result.vulnerable, is_false);
  assert_that (configuration_query_count, is_equal_to (0));
}

Ensure (manage_cve_scan, negate_applies_after_or_criterion_short_circuit)
{
  cpe_evaluation_t result;
  fixture->configuration->root = fixture->fxos;
  fixture->fxos->negate = TRUE;

  result = evaluate_cpe_configuration (
    fixture->configuration, fixture->inventory, &fixture->target->cpe);

  assert_that (result.match, is_false);
  assert_that (result.vulnerable, is_false);
  assert_that (configuration_query_count, is_equal_to (0));
}

Ensure (manage_cve_scan, empty_platform_does_not_satisfy_and_configuration)
{
  cpe_evaluation_t result;
  fixture->hardware->operator= CPE_OPERATOR_AND;
  g_ptr_array_set_size (fixture->hardware->criteria, 0);

  result = evaluate_cpe_configuration (
    fixture->configuration, fixture->inventory, &fixture->target->cpe);

  assert_that (result.match, is_false);
  assert_that (result.vulnerable, is_false);
  assert_that (configuration_query_count, is_equal_to (0));
}

Ensure (manage_cve_scan, empty_and_does_not_match)
{
  cpe_evaluation_t result;
  fixture->configuration->root = fixture->fxos;
  fixture->fxos->operator= CPE_OPERATOR_AND;
  fixture->fxos->negate = FALSE;
  g_ptr_array_set_size (fixture->fxos->criteria, 0);

  result = evaluate_cpe_configuration (
    fixture->configuration, fixture->inventory, &fixture->target->cpe);

  assert_that (result.match, is_false);
  assert_that (result.vulnerable, is_false);
  assert_that (configuration_query_count, is_equal_to (0));
}

Ensure (manage_cve_scan, negated_empty_and_matches)
{
  cpe_evaluation_t result;
  fixture->configuration->root = fixture->fxos;
  fixture->fxos->operator= CPE_OPERATOR_AND;
  fixture->fxos->negate = TRUE;
  g_ptr_array_set_size (fixture->fxos->criteria, 0);

  result = evaluate_cpe_configuration (
    fixture->configuration, fixture->inventory, &fixture->target->cpe);

  assert_that (result.match, is_true);
  assert_that (result.vulnerable, is_false);
  assert_that (configuration_query_count, is_equal_to (0));
}

Ensure (manage_cve_scan, empty_or_does_not_match)
{
  cpe_evaluation_t result;
  fixture->configuration->root = fixture->fxos;
  fixture->fxos->operator= CPE_OPERATOR_OR;
  fixture->fxos->negate = FALSE;
  g_ptr_array_set_size (fixture->fxos->criteria, 0);

  result = evaluate_cpe_configuration (
    fixture->configuration, fixture->inventory, &fixture->target->cpe);

  assert_that (result.match, is_false);
  assert_that (result.vulnerable, is_false);
  assert_that (configuration_query_count, is_equal_to (0));
}

Ensure (manage_cve_scan, negated_empty_or_matches)
{
  cpe_evaluation_t result;
  fixture->configuration->root = fixture->fxos;
  fixture->fxos->operator= CPE_OPERATOR_OR;
  fixture->fxos->negate = TRUE;
  g_ptr_array_set_size (fixture->fxos->criteria, 0);

  result = evaluate_cpe_configuration (
    fixture->configuration, fixture->inventory, &fixture->target->cpe);

  assert_that (result.match, is_true);
  assert_that (result.vulnerable, is_false);
  assert_that (configuration_query_count, is_equal_to (0));
}

Ensure (manage_cve_scan, loads_complete_configuration_in_one_query)
{
  cpe_node_t *fxos, *hardware;
  cpe_criterion_t *criterion;

  loaded_configuration = load_cpe_configuration (ROOT_NODE);

  assert_that (loaded_configuration, is_non_null);
  assert_that (configuration_query_count, is_equal_to (1));
  assert_that (strstr (last_configuration_query,
                       "LEFT JOIN scap.cpe_nodes_match_criteria"),
               is_non_null);
  assert_that (loaded_configuration->nodes->len, is_equal_to (3));
  assert_that (loaded_configuration->root->children->len, is_equal_to (2));
  assert_that (loaded_configuration->root->criteria->len, is_equal_to (0));
  fxos = g_ptr_array_index (loaded_configuration->root->children, 0);
  hardware = g_ptr_array_index (loaded_configuration->root->children, 1);
  assert_that (fxos->criteria->len, is_equal_to (2));
  assert_that (hardware->negate, is_true);
  criterion = g_ptr_array_index (fxos->criteria, 1);
  assert_that (criterion->version_start_incl, is_equal_to_string ("7.0"));
  assert_that (criterion->version_start_excl, is_equal_to_string ("6.5"));
  assert_that (criterion->version_end_incl, is_equal_to_string ("8.0"));
  assert_that (criterion->version_end_excl, is_equal_to_string ("9.0"));
  assert_that (criterion->vulnerable, is_true);
}

Ensure (manage_cve_scan, loaded_configuration_evaluates_without_more_queries)
{
  cpe_evaluation_t result;
  arrange_target (fixture, "cpe:/o:cisco:fxos:7.0");
  g_ptr_array_add (fixture->inventory,
                   new_cpe_host_product (fixture->target->uri));
  loaded_configuration = load_cpe_configuration (ROOT_NODE);

  result = evaluate_cpe_configuration (loaded_configuration, fixture->inventory,
                                       &fixture->target->cpe);

  assert_that (result.match, is_true);
  assert_that (result.vulnerable, is_true);
  assert_that (configuration_query_count, is_equal_to (1));
}

Ensure (manage_cve_scan,
        another_inventory_version_does_not_mark_target_vulnerable)
{
  cpe_evaluation_t result;
  g_ptr_array_add (fixture->inventory,
                   new_cpe_host_product ("cpe:/o:cisco:fxos:7.0"));
  loaded_configuration = load_cpe_configuration (ROOT_NODE);

  result = evaluate_cpe_configuration (loaded_configuration, fixture->inventory,
                                       &fixture->target->cpe);

  assert_that (result.match, is_true);
  assert_that (result.vulnerable, is_false);
  assert_that (configuration_query_count, is_equal_to (1));
}

Ensure (manage_cve_scan, loaded_configuration_rejects_excluded_hardware)
{
  cpe_evaluation_t result;
  arrange_target (fixture, "cpe:/o:cisco:fxos:7.0");
  g_ptr_array_add (fixture->inventory,
                   new_cpe_host_product (fixture->target->uri));
  g_ptr_array_add (fixture->inventory, new_cpe_host_product (hardware_cpe));
  loaded_configuration = load_cpe_configuration (ROOT_NODE);

  result = evaluate_cpe_configuration (loaded_configuration, fixture->inventory,
                                       &fixture->target->cpe);

  assert_that (result.match, is_false);
  assert_that (result.vulnerable, is_false);
  assert_that (configuration_query_count, is_equal_to (1));
}

Ensure (manage_cve_scan, missing_match_string_preserves_other_or_matches)
{
  cpe_evaluation_t result;
  stored_rows[2].criteria = NULL;
  loaded_configuration = load_cpe_configuration (ROOT_NODE);

  result = evaluate_cpe_configuration (loaded_configuration, fixture->inventory,
                                       &fixture->target->cpe);

  assert_that (result.match, is_true);
  assert_that (result.vulnerable, is_false);
  assert_that (configuration_query_count, is_equal_to (1));
}

Ensure (manage_cve_scan, missing_match_string_remains_false_in_and_node)
{
  cpe_evaluation_t result;
  stored_rows[2].criteria = NULL;
  stored_rows[1].operator= "AND";
  stored_rows[2].operator= "AND";
  loaded_configuration = load_cpe_configuration (ROOT_NODE);

  result = evaluate_cpe_configuration (loaded_configuration, fixture->inventory,
                                       &fixture->target->cpe);

  assert_that (result.match, is_false);
  assert_that (result.vulnerable, is_false);
  assert_that (configuration_query_count, is_equal_to (1));
}

Ensure (manage_cve_scan, missing_root_rejects_configuration)
{
  first_stored_row = 1;

  loaded_configuration = load_cpe_configuration (ROOT_NODE);

  assert_that (loaded_configuration, is_null);
  assert_that (configuration_query_count, is_equal_to (1));
}

Ensure (manage_cve_scan, invalid_operator_rejects_configuration)
{
  stored_rows[0].operator= "XOR";

  loaded_configuration = load_cpe_configuration (ROOT_NODE);

  assert_that (loaded_configuration, is_null);
  assert_that (configuration_query_count, is_equal_to (1));
}

Ensure (manage_cve_scan, empty_configuration_query_returns_no_configuration)
{
  stored_row_count = 0;

  loaded_configuration = load_cpe_configuration (ROOT_NODE);

  assert_that (loaded_configuration, is_null);
  assert_that (configuration_query_count, is_equal_to (1));
}

Ensure (manage_cve_scan, unavailable_criterion_under_negated_root_is_rejected)
{
  stored_rows[2].criteria = NULL;
  stored_rows[0].negate = TRUE;

  loaded_configuration = load_cpe_configuration (ROOT_NODE);

  assert_that (loaded_configuration, is_null);
  assert_that (configuration_query_count, is_equal_to (1));
}

Ensure (manage_cve_scan, unavailable_criterion_under_negated_node_is_rejected)
{
  stored_rows[2].criteria = NULL;
  stored_rows[1].negate = TRUE;
  stored_rows[2].negate = TRUE;

  loaded_configuration = load_cpe_configuration (ROOT_NODE);

  assert_that (loaded_configuration, is_null);
  assert_that (configuration_query_count, is_equal_to (1));
}

Ensure (manage_cve_scan, loads_inventory_once_and_parses_all_products)
{
  cpe_host_product_t *fxos, *hardware;
  hardware_present = TRUE;

  loaded_inventory = load_cpe_host_inventory (1);

  assert_that (inventory_query_count, is_equal_to (1));
  assert_that (requested_inventory_report_host, is_equal_to (1));
  assert_that (loaded_inventory->len, is_equal_to (2));
  fxos = g_ptr_array_index (loaded_inventory, 0);
  hardware = g_ptr_array_index (loaded_inventory, 1);
  assert_that (fxos->uri, is_equal_to_string (fxos_cpe));
  assert_that (fxos->cpe.version, is_equal_to_string ("6\\.4\\.0"));
  assert_that (hardware->cpe.product, is_equal_to_string ("firepower_1010"));
}

Ensure (manage_cve_scan, caches_successful_loads)
{
  cpe_configuration_t *first, *cached;
  configuration_cache = g_hash_table_new_full (g_int64_hash, g_int64_equal,
                                               g_free, free_cpe_configuration);
  first = get_cpe_configuration (configuration_cache, ROOT_NODE);

  cached = get_cpe_configuration (configuration_cache, ROOT_NODE);

  assert_that (first, is_non_null);
  assert_that (cached, is_equal_to (first));
  assert_that (configuration_query_count, is_equal_to (1));
  assert_that (g_hash_table_size (configuration_cache), is_equal_to (1));
}

Ensure (manage_cve_scan, caches_failed_loads)
{
  cpe_configuration_t *first, *cached;
  stored_row_count = 0;
  configuration_cache = g_hash_table_new_full (g_int64_hash, g_int64_equal,
                                               g_free, free_cpe_configuration);
  first = get_cpe_configuration (configuration_cache, ROOT_NODE);

  cached = get_cpe_configuration (configuration_cache, ROOT_NODE);

  assert_that (first, is_null);
  assert_that (cached, is_null);
  assert_that (configuration_query_count, is_equal_to (1));
  assert_that (g_hash_table_size (configuration_cache), is_equal_to (1));
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite = create_test_suite ();

  add_test_with_context (suite, manage_cve_scan,
                         and_rule_requires_hardware_as_well_as_fxos);
  add_test_with_context (suite, manage_cve_scan,
                         and_rule_matches_when_hardware_and_fxos_are_present);
  add_test_with_context (
    suite, manage_cve_scan,
    and_rule_rejects_missing_hardware_when_hardware_is_first);
  add_test_with_context (suite, manage_cve_scan,
                         out_of_range_criterion_does_not_mark_host_vulnerable);
  add_test_with_context (suite, manage_cve_scan,
                         and_criteria_do_not_inherit_previous_match);
  add_test_with_context (suite, manage_cve_scan,
                         or_children_match_when_application_is_first);
  add_test_with_context (suite, manage_cve_scan,
                         or_children_match_when_hardware_is_first);
  add_test_with_context (suite, manage_cve_scan,
                         negated_and_matches_when_hardware_is_absent);
  add_test_with_context (suite, manage_cve_scan,
                         negated_and_rejects_matching_operands);
  add_test_with_context (suite, manage_cve_scan,
                         negated_or_rejects_matching_application);
  add_test_with_context (suite, manage_cve_scan,
                         negated_or_rejects_matching_application_and_hardware);
  add_test_with_context (suite, manage_cve_scan,
                         negated_environment_matches_when_absent);
  add_test_with_context (suite, manage_cve_scan,
                         negated_environment_matches_when_absent_and_first);
  add_test_with_context (suite, manage_cve_scan,
                         negated_environment_rejects_present_hardware);
  add_test_with_context (
    suite, manage_cve_scan,
    negated_environment_rejects_present_hardware_when_first);
  add_test_with_context (suite, manage_cve_scan,
                         nested_negation_matches_when_hardware_is_present);
  add_test_with_context (suite, manage_cve_scan,
                         nested_negation_rejects_absent_hardware);
  add_test_with_context (
    suite, manage_cve_scan,
    negated_leaf_matches_absence_without_creating_vulnerability);
  add_test_with_context (suite, manage_cve_scan,
                         negated_leaf_rejects_present_hardware);
  add_test_with_context (suite, manage_cve_scan,
                         negate_applies_after_and_criterion_short_circuit);
  add_test_with_context (suite, manage_cve_scan,
                         negate_applies_after_or_criterion_short_circuit);
  add_test_with_context (suite, manage_cve_scan,
                         empty_platform_does_not_satisfy_and_configuration);
  add_test_with_context (suite, manage_cve_scan, empty_and_does_not_match);
  add_test_with_context (suite, manage_cve_scan, negated_empty_and_matches);
  add_test_with_context (suite, manage_cve_scan, empty_or_does_not_match);
  add_test_with_context (suite, manage_cve_scan, negated_empty_or_matches);
  add_test_with_context (suite, manage_cve_scan,
                         loads_complete_configuration_in_one_query);
  add_test_with_context (suite, manage_cve_scan,
                         loaded_configuration_evaluates_without_more_queries);
  add_test_with_context (
    suite, manage_cve_scan,
    another_inventory_version_does_not_mark_target_vulnerable);
  add_test_with_context (suite, manage_cve_scan,
                         loaded_configuration_rejects_excluded_hardware);
  add_test_with_context (suite, manage_cve_scan,
                         missing_match_string_preserves_other_or_matches);
  add_test_with_context (suite, manage_cve_scan,
                         missing_match_string_remains_false_in_and_node);
  add_test_with_context (suite, manage_cve_scan,
                         missing_root_rejects_configuration);
  add_test_with_context (suite, manage_cve_scan,
                         invalid_operator_rejects_configuration);
  add_test_with_context (suite, manage_cve_scan,
                         empty_configuration_query_returns_no_configuration);
  add_test_with_context (suite, manage_cve_scan,
                         unavailable_criterion_under_negated_root_is_rejected);
  add_test_with_context (suite, manage_cve_scan,
                         unavailable_criterion_under_negated_node_is_rejected);
  add_test_with_context (suite, manage_cve_scan,
                         loads_inventory_once_and_parses_all_products);
  add_test_with_context (suite, manage_cve_scan, caches_successful_loads);
  add_test_with_context (suite, manage_cve_scan, caches_failed_loads);
  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());
  destroy_test_suite (suite);
  return ret;
}
