/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Modify Agent-Controller scan-agent configuration.
 *
 */

#if ENABLE_AGENTS

#include "gmp_agent_control_scan_agent_config.h"
#include "manage_agent_control_scan_config.h"
#include "manage_sql.h"


#include <glib.h>

#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "md gmp"

/* ---------- MODIFY_AGENT_CONTROL_SCAN_CONFIG ---------- */
/**
 * @brief The modify_agent_control_scan_config command.
 */
typedef struct
{
  context_data_t *ctx;
} modify_scan_cfg_ctx_t;

static modify_scan_cfg_ctx_t modify_scan_cfg_ctx;

/**
 * @brief Reset command data.
 */
static void
modify_agent_control_scan_config_reset (void)
{
  if (modify_scan_cfg_ctx.ctx && modify_scan_cfg_ctx.ctx->first)
    {
      free_entity (modify_scan_cfg_ctx.ctx->first->data);
      g_slist_free_1 (modify_scan_cfg_ctx.ctx->first);
    }
  g_free (modify_scan_cfg_ctx.ctx);
  memset (&modify_scan_cfg_ctx, 0, sizeof (modify_scan_cfg_ctx));
}

/**
 * @brief Handle command start.
 *
 * @param[in] gmp_parser        Active GMP parser (unused).
 * @param[in] attribute_names   Null-terminated array of attribute names.
 * @param[in] attribute_values  Null-terminated array of attribute values.
 */
void
modify_agent_control_scan_config_start (gmp_parser_t *gmp_parser,
                                        const gchar **attribute_names,
                                        const gchar **attribute_values)
{
  (void) gmp_parser;
  (void) attribute_names;
  (void) attribute_values;
  memset (&modify_scan_cfg_ctx, 0, sizeof (modify_scan_cfg_ctx));
  modify_scan_cfg_ctx.ctx = g_malloc0 (sizeof (context_data_t));
  xml_handle_start_element (modify_scan_cfg_ctx.ctx,
                            "modify_agent_control_scan_config",
                            attribute_names,
                            attribute_values);
}

/**
 * @brief Handle command start element.
 *
 * @param[in] gmp_parser        Active GMP parser (unused).
 * @param[in] name              Element name.
 * @param[in] attribute_names   Null-terminated array of attribute names.
 * @param[in] attribute_values  Null-terminated array of attribute values.
 */
void
modify_agent_control_scan_config_element_start (gmp_parser_t *gmp_parser,
                                                const gchar *name,
                                                const gchar **attribute_names,
                                                const gchar **attribute_values)
{
  xml_handle_start_element (modify_scan_cfg_ctx.ctx, name,
                            attribute_names, attribute_values);
}

/**
 * @brief Add text to element in the command
 *
 * @param[in] text      the text to add.
 * @param[in] len  the length of the text being added.
 */
void
modify_agent_control_scan_config_element_text (const gchar *text, gsize len)
{
  xml_handle_text (modify_scan_cfg_ctx.ctx, text, len);
}

/**
 * @brief Run modify_agent_control_scan_config command
 *
 * @param[in] gmp_parser  current instance of GMP parser.
 * @param[in] error       the errors, if any.
 */
void
modify_agent_control_scan_config_run (gmp_parser_t *gmp_parser, GError **error)
{
  const char *scanner_uuid;
  entity_t root = (entity_t) modify_scan_cfg_ctx.ctx->first->data;

  scanner_uuid = entity_attribute (root, "agent_control_id");

  if (!scanner_uuid || !is_uuid (scanner_uuid))
    {
      SENDF_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("modify_agent_control_scan_config",
          "Missing or invalid scanner UUID"));
      modify_agent_control_scan_config_reset ();
      return;
    }

  scanner_t scanner = 0;
  if (find_scanner_with_permission (scanner_uuid, &scanner, "get_scanners"))
    {
      if (send_find_error_to_client ("modify_agent_control_scan_config",
                                     "scanner", NULL, gmp_parser))
        error_send_to_client (error);
      modify_agent_control_scan_config_reset ();
      return;
    }
  if (scanner == 0)
    {
      if (send_find_error_to_client ("modify_agent_control_scan_config",
                                     "scanner", NULL, gmp_parser))
        error_send_to_client (error);
      modify_agent_control_scan_config_reset ();
      return;
    }

  int type = scanner_type (scanner);
  if (type != SCANNER_TYPE_AGENT_CONTROLLER &&
      type != SCANNER_TYPE_AGENT_CONTROLLER_SENSOR)
    {
      SENDF_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("modify_agent_control_scan_config",
          "Scanner is not an Agent Controller"));
      modify_agent_control_scan_config_reset ();
      return;
    }

  /* <config>… */
  entity_t cfg_e = entity_child (root, "config");
  if (!cfg_e)
    {
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("modify_agent_control_scan_config",
          "Missing <config>"));
      modify_agent_control_scan_config_reset ();
      return;
    }

  agent_controller_scan_agent_config_t cfg =
    agent_controller_scan_agent_config_new ();
  build_scan_agent_config_from_entity (cfg_e, cfg);

  GPtrArray *errs = NULL;
  int rc = modify_agent_control_scan_config (scanner, cfg, &errs);

  switch (rc)
    {
    case 0:
      /* Success */
      SENDF_TO_CLIENT_OR_FAIL (XML_OK ("modify_agent_control_scan_config"));
      log_event ("agent_control_scan_config", "Agent Control Scan Config",
                 scanner_uuid, "modified");
      modify_agent_control_scan_config_reset ();
      return;

    case -1:
      /* Invalid arguments (scanner == 0 or cfg == NULL) */
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("modify_agent_control_scan_config",
          "Invalid arguments: missing scanner or <config>"));
      log_event_fail ("agent_control_scan_config", "Agent Control Scan Config",
                      scanner_uuid, "modified");
      modify_agent_control_scan_config_reset ();
      return;

    case -2:
      /* Connector creation failed */
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_UNAVAILABLE ("modify_agent_control_scan_config",
          "Could not connect to Agent-Controller"));
      log_event_fail ("agent_control_scan_config", "Agent Control Scan Config",
                      scanner_uuid, "modified");
      modify_agent_control_scan_config_reset ();
      return;

    case -3:
      gchar *status_text = concat_error_messages (
        errs, "; ", "Validation failed for config: ");
      if (!status_text)
        status_text = g_markup_escape_text ("Validation failed for config.",
                                            -1);

      gchar *xml = g_markup_printf_escaped (
        "<modify_agent_control_scan_config_response status=\""
        STATUS_ERROR_SYNTAX
        "\" status_text=\"%s\"/>",
        status_text ? status_text : "Validation failed for <config>."
        );

      if (send_to_client (xml, gmp_parser->client_writer,
                          gmp_parser->client_writer_data))
        error_send_to_client (error);

      g_free (xml);
      g_free (status_text);
      if (errs)
        g_ptr_array_free (errs, TRUE);
      log_event_fail ("agent_control_scan_config", "Agent Control Scan Config",
                      scanner_uuid, "modified");
      modify_agent_control_scan_config_reset ();
      return;

    case -4:
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_UNAVAILABLE ("modify_agent_control_scan_config",
          "Agent-Controller update failed"));
      log_event_fail ("agent_control_scan_config", "Agent Control Scan Config",
                      scanner_uuid, "modified");
      modify_agent_control_scan_config_reset ();
      return;

    default:
      SEND_TO_CLIENT_OR_FAIL (
        XML_INTERNAL_ERROR ("modify_agent_control_scan_config"));
      log_event_fail ("agent_control_scan_config", "Agent Control Scan Config",
                      scanner_uuid, "modified");
      modify_agent_control_scan_config_reset ();
      return;
    }

  SENDF_TO_CLIENT_OR_FAIL (XML_OK ("modify_agent_control_scan_config"));
  modify_agent_control_scan_config_reset ();
}

/**
 * @brief End element in the command
 *
 *
 * @param[in] gmp_parser  current instance of GMP parser.
 * @param[in] error       the errors, if any.
 * @param[in] name        name of element.
 *
 * @return 1 if the command ran successfully, 0 otherwise.
 */
int
modify_agent_control_scan_config_element_end (gmp_parser_t *gmp_parser,
                                              GError **error,
                                              const gchar *name)
{
  xml_handle_end_element (modify_scan_cfg_ctx.ctx, name);
  if (modify_scan_cfg_ctx.ctx->done)
    {
      modify_agent_control_scan_config_run (gmp_parser, error);
      return 1;
    }
  return 0;
}

/**
 * @brief Populate an Agent-Controller scan config from a <config> subtree.
 *
 * @param[in] root Entity node representing the <config> subtree
 *                 (i.e., the parent of <agent_control>, <agent_script_executor>,
 *                 and <heartbeat> elements).
 * @param[in,out] out_cfg Pre-allocated config object to populate. Must not be NULL.
 *
 * @return 0 on success; -1 if @p out_cfg is NULL.
 */
int
build_scan_agent_config_from_entity (
  entity_t root,
  agent_controller_scan_agent_config_t out_cfg)
{
  if (!out_cfg)
    return -1;

  entity_t e = NULL;

  /* <agent_control><retry>… */
  entity_t ac = entity_child (root, "agent_control");
  if (ac)
    {
      entity_t retry = entity_child (ac, "retry");
      if (retry)
        {
          e = entity_child (retry, "attempts");
          if (e)
            out_cfg->agent_control.retry.attempts =
              atoi (entity_text (e) ? entity_text (e) : "0");

          e = entity_child (retry, "delay_in_seconds");
          if (e)
            out_cfg->agent_control.retry.delay_in_seconds =
              atoi (entity_text (e) ? entity_text (e) : "0");

          e = entity_child (retry, "max_jitter_in_seconds");
          if (e)
            out_cfg->agent_control.retry.max_jitter_in_seconds =
              atoi (entity_text (e) ? entity_text (e) : "0");
        }
    }

  /* <agent_script_executor>… */
  entity_t se = entity_child (root, "agent_script_executor");
  if (se)
    {
      e = entity_child (se, "bulk_size");
      if (e)
        out_cfg->agent_script_executor.bulk_size =
          atoi (entity_text (e) ? entity_text (e) : "0");

      e = entity_child (se, "bulk_throttle_time_in_ms");
      if (e)
        out_cfg->agent_script_executor.bulk_throttle_time_in_ms =
          atoi (entity_text (e) ? entity_text (e) : "0");

      e = entity_child (se, "indexer_dir_depth");
      if (e)
        out_cfg->agent_script_executor.indexer_dir_depth =
          atoi (entity_text (e) ? entity_text (e) : "0");

      e = entity_child (se, "period_in_seconds");
      if (e)
        out_cfg->agent_script_executor.period_in_seconds =
          atoi (entity_text (e) ? entity_text (e) : "0");

      /* <scheduler_cron_time><item>...</item>... */
      entity_t sct = entity_child (se, "scheduler_cron_time");
      if (sct)
        {
          GPtrArray *arr = g_ptr_array_new_with_free_func (g_free);
          for (GSList *n = sct->entities; n; n = n->next)
            {
              entity_t it = n->data;
              if (it && strcmp (entity_name (it), "item") == 0)
                {
                  const gchar *txt = entity_text (it);
                  g_ptr_array_add (arr, g_strdup (txt ? txt : ""));
                }
            }
          if (arr->len == 0)
            g_ptr_array_free (arr, TRUE);
          else
            out_cfg->agent_script_executor.scheduler_cron_time = arr;
        }
    }

  /* <heartbeat>… */
  entity_t hb = entity_child (root, "heartbeat");
  if (hb)
    {
      e = entity_child (hb, "interval_in_seconds");
      if (e)
        out_cfg->heartbeat.interval_in_seconds =
          atoi (entity_text (e) ? entity_text (e) : "0");

      e = entity_child (hb, "miss_until_inactive");
      if (e)
        out_cfg->heartbeat.miss_until_inactive =
          atoi (entity_text (e) ? entity_text (e) : "0");
    }

  return 0;
}


#endif /* ENABLE_AGENTS */