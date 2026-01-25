/* Copyright (C) 2009-2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_assets.h"
#include "manage_acl.h"
#include "manage_sql.h"
#include "manage_sql_filters.h"
#if ENABLE_AGENTS
#include "manage_sql_groups.h"
#endif
#if ENABLE_CONTAINER_SCANNING
#include "manage_sql_oci_image_targets.h"
#endif
#include "manage_sql_tls_certificates.h"
#include "sql.h"

#include <gvm/base/array.h>
#include <gvm/base/hosts.h>
#include <gvm/util/xmlutils.h>

/**
 * @file
 * @brief GVM management layer: Asset SQL
 *
 * The Asset SQL for the GVM management layer.
 */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * \page asset_rules Ruleset for updating assets from scan detections
 *
 * During a scan various assets are identfied. The findings are by default
 * used to update the asset database. Since assets may already be present in
 * the database or even be present with contradictive properties, a ruleset
 * defines how the asset database is updated upon findings.
 *
 * Hosts
 * -----
 *
 * When a host is detected, and there is at least one asset host that has the
 * same name and owner as the detected host, and whose identifiers all have
 * the same values as the identifiers of the detected host, then the most
 * recent such asset host is used. Otherwise a new asset host is created.
 * Either way the identifiers are added to the asset host. It does not matter
 * if the asset host has fewer identifiers than detected, as long as the
 * existing identifiers match.
 *
 * At the beginning of a scan, when a host is first detected, the decision
 * about which asset host to use is made by \ref host_notice.  At the end
 * of the scan, if the host has identifiers, then this decision is revised
 * by \ref hosts_set_identifiers to take the identifiers into account.
 *
 * Host identifiers can be ip, hostname, MAC, OS or ssh-key.
 *
 * This documentation includes some pseudo-code and tabular definition.
 * Eventually one of them will repalce the other.
 *
 * Name    : The assigned name (usually the IP)
 * IP      : The detected IP
 * Hostname: The detected Hostname
 * OS:     : The detected OS
 *
 * If IP And Not Hostname:
 *   If Not Assets.Host(id=Name) And Not Assets.Host(attrib=IP, IP):
 *     Assets.Host.New(id=Name, ip=IP)
 *   If Assets.Host(id=Name) == 1:
 *     Assets.Host.Add(id=Name, ip=IP)
 *
 * This pseudo-code is equivalent to the first two rows of:
 *
 * Detection                     | Asset State                                                                 |     Asset Update
 * ----------------------------- | --------------------------------------------------------------------------- | -----------------------------
 * IP address X.                 | No host with Name=X or any ip=X.                                            | Create host with Name=X and ip=X.
 * IP address X.                 | Host A with Name=X.                                                         | Add ip=X to host A.
 * IP address X.                 | (Host A with Name=X and ip=X) and (Host B with Name=X and ip=X).            | Add ip=X to host (Newest(A,B)).
 * IP address X with Hostname Y. | Host A with Name=X and ip=X.                                                | Add ip=X and hostname=Y to host A.
 * IP address X with Hostname Y. | Host A with Name=X and ip=X and hostname=Y.                                 | Add ip=X and hostname=Y to host A.
 * IP address X with Hostname Y. | Host A with Name=X and ip=X and hostname<>Y.                                | Create host with Name=X, ip=X and hostname=Y.
 * IP address X with Hostname Y. | Host A with Name=X and ip=X and hostname=Y and host B with Name=X and ip=X. | Add ip=X and hostname=Y to host (Newst(A,B)).
 *
 * Follow up action: If a MAC, OS or ssh-key was detected, then the respective
 * identifiers are added to the asset host selected during asset update.
 *
 * Operating Systems
 * -----------------
 *
 * If OS:
 *   If Not Assets.OS(id=OS):
 *     Assets.OS.New(id=OS)
 *
 * This pseudo-code is equivalent to:
 *
 * Detection | Asset State        | Asset Update
 * --------- | ------------------ | ------------------------
 * OS X.     | No OS with Name=X. | Create OS with Name=X.
 * OS X.     | OS with Name=X.    | No action.
 */

/**
 * @brief Host identifier type.
 */
typedef struct
{
  gchar *ip;                ///< IP of host.
  gchar *name;              ///< Name of identifier, like "hostname".
  gchar *value;             ///< Value of identifier.
  gchar *source_type;       ///< Type of identifier source, like "Report Host".
  gchar *source_id;         ///< ID of source.
  gchar *source_data;       ///< Extra data for source.
} identifier_t;

/**
 * @brief Host identifiers for the current scan.
 */
array_t *identifiers = NULL;

/**
 * @brief Unique hosts listed in host_identifiers.
 */
array_t *identifier_hosts = NULL;

/**
 * @brief Host identifiers collected during report parsing.
 *
 * Used to create snapshots or other post-processing that must not depend on
 * the task preference "in_assets".
 */
array_t *snapshot_identifiers = NULL;

/**
 * @brief Unique hosts listed in scan_identifiers.
 */
array_t *snapshot_identifier_hosts = NULL;

/**
 * @brief Column indices that match init_asset_snapshot_iterator().
 */
typedef enum
{
  AS_COL_ID = 0,
  AS_COL_UUID = 1,
  AS_COL_TASK_ID = 2,
  AS_COL_REPORT_ID = 3,
  AS_COL_ASSET_TYPE = 4,
  AS_COL_IP_ADDRESS = 5,
  AS_COL_HOSTNAME = 6,
  AS_COL_MAC_ADDRESS = 7,
  AS_COL_AGENT_ID = 8,
  AS_COL_CONTAINER_DIGEST = 9,
  AS_COL_ASSET_KEY = 10,
  AS_COL_CREATION_TIME = 11,
  AS_COL_MODIFICATION_TIME = 12
} asset_snapshot_col_t;

static int
report_host_dead (report_host_t);

/**
 * @brief Return the UUID of the asset associated with a result host.
 *
 * @param[in]  host    Host value from result.
 * @param[in]  result  Result.
 *
 * @return Asset UUID.
 */
char *
result_host_asset_id (const char *host, result_t result)
{
  gchar *quoted_host;
  char *asset_id;

  quoted_host = sql_quote (host);
  asset_id = sql_string ("SELECT uuid FROM hosts"
                         " WHERE id = (SELECT host FROM host_identifiers"
                         "             WHERE source_type = 'Report Host'"
                         "             AND name = 'ip'"
                         "             AND source_id"
                         "                 = (SELECT uuid"
                         "                    FROM reports"
                         "                    WHERE id = (SELECT report"
                         "                                FROM results"
                         "                                WHERE id = %llu))"
                         "             AND value = '%s'"
                         "             LIMIT 1);",
                         result,
                         quoted_host);
  g_free (quoted_host);
  return asset_id;
}

/**
 * @brief Return the UUID of a host.
 *
 * @param[in]  host  Host.
 *
 * @return Host UUID.
 */
char*
host_uuid (resource_t host)
{
  return sql_string ("SELECT uuid FROM hosts WHERE id = %llu;",
                     host);
}

/**
 * @brief Identify a host, given an identifier.
 *
 * Find a host which has an identifier of the same name and value, and
 * which has no identifiers of the same name and a different value.
 *
 * @param[in]  host_name         Host name.
 * @param[in]  identifier_name   Host identifier name.
 * @param[in]  identifier_value  Value of host identifier.
 * @param[in]  source_type       Source of identification: result.
 * @param[in]  source            Source identifier.
 *
 * @return Host if exists, else 0.
 */
static host_t
host_identify (const char *host_name, const char *identifier_name,
               const char *identifier_value, const char *source_type,
               const char *source)
{
  host_t host = 0;
  gchar *quoted_host_name, *quoted_identifier_name, *quoted_identifier_value;

  quoted_host_name = sql_quote (host_name);
  quoted_identifier_name = sql_quote (identifier_name);
  quoted_identifier_value = sql_quote (identifier_value);

  switch (sql_int64 (&host,
                     "SELECT hosts.id FROM hosts, host_identifiers"
                     " WHERE hosts.name = '%s'"
                     " AND hosts.owner = (SELECT id FROM users"
                     "                    WHERE uuid = '%s')"
                     " AND host = hosts.id"
                     " AND host_identifiers.owner = (SELECT id FROM users"
                     "                               WHERE uuid = '%s')"
                     " AND host_identifiers.name = '%s'"
                     " AND value = '%s';",
                     quoted_host_name,
                     current_credentials.uuid,
                     current_credentials.uuid,
                     quoted_identifier_name,
                     quoted_identifier_value))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        host = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        host = 0;
        break;
    }

  if (host == 0)
    switch (sql_int64 (&host,
                       "SELECT id FROM hosts"
                       " WHERE name = '%s'"
                       " AND owner = (SELECT id FROM users"
                       "              WHERE uuid = '%s')"
                       " AND NOT EXISTS (SELECT * FROM host_identifiers"
                       "                 WHERE host = hosts.id"
                       "                 AND owner = (SELECT id FROM users"
                       "                              WHERE uuid = '%s')"
                       "                 AND name = '%s');",
                       quoted_host_name,
                       current_credentials.uuid,
                       current_credentials.uuid,
                       quoted_identifier_name))
      {
        case 0:
          break;
        case 1:        /* Too few rows in result of query. */
          host = 0;
          break;
        default:       /* Programming error. */
          assert (0);
        case -1:
          host = 0;
          break;
      }

  g_free (quoted_host_name);
  g_free (quoted_identifier_name);
  g_free (quoted_identifier_value);

  return host;
}

/**
 * @brief Notice a host.
 *
 * When a host is detected during a scan, this makes the decision about which
 * asset host is used for the host, as described in \ref asset_rules.  This
 * decision is revised at the end of the scan by \ref hosts_set_identifiers if
 * there are any identifiers for the host.
 *
 * @param[in]  host_name         Name of host.
 * @param[in]  identifier_type   Type of host identifier.
 * @param[in]  identifier_value  Value of host identifier.
 * @param[in]  source_type       Type of source identifier
 * @param[in]  source_id         Source identifier.
 * @param[in]  check_add_to_assets  Whether to check the 'Add to Assets'
 *                                  task preference.
 * @param[in]  check_for_existing_identifier  Whether to check for an existing
 *                                            identifier like this one.  Used
 *                                            for slaves, which call this
 *                                            repeatedly.
 *
 * @return Host if existed, else 0.
 */
static host_t
host_notice (const char *host_name, const char *identifier_type,
             const char *identifier_value, const char *source_type,
             const char *source_id, int check_add_to_assets,
             int check_for_existing_identifier)
{
  host_t host;
  gchar *quoted_identifier_value, *quoted_identifier_type, *quoted_source_type;
  gchar *quoted_source_id;

  /* Only add to assets if "Add to Assets" is set on the task. */
  if (check_add_to_assets
      && g_str_has_prefix (source_type, "Report")
      && sql_int ("SELECT value = 'no' FROM task_preferences"
                  " WHERE task = (SELECT task FROM reports WHERE uuid = '%s')"
                  " AND name = 'in_assets';",
                  source_id))
    return 0;

  host = host_identify (host_name, identifier_type, identifier_value,
                        source_type, source_id);
  if (host == 0)
    {
      gchar *quoted_host_name;
      quoted_host_name = sql_quote (host_name);
      sql ("INSERT into hosts"
           " (uuid, owner, name, comment, creation_time, modification_time)"
           " VALUES"
           " (make_uuid (), (SELECT id FROM users WHERE uuid = '%s'), '%s', '',"
           "  m_now (), m_now ());",
           current_credentials.uuid,
           quoted_host_name);
      g_free (quoted_host_name);

      host = sql_last_insert_id ();
    }

  quoted_identifier_value = sql_quote (identifier_value);
  quoted_source_id = sql_quote (source_id);
  quoted_source_type = sql_quote (source_type);
  quoted_identifier_type = sql_quote (identifier_type);

  if (check_for_existing_identifier
      && sql_int ("SELECT EXISTS (SELECT * FROM host_identifiers"
                  "               WHERE host = %llu"
                  "               AND owner = (SELECT id FROM users WHERE uuid = '%s')"
                  "               AND name = '%s'"
                  "               AND value = '%s'"
                  "               AND source_type = '%s'"
                  "               AND source_id = '%s');",
                  host,
                  current_credentials.uuid,
                  quoted_identifier_type,
                  quoted_identifier_value,
                  quoted_source_type,
                  quoted_source_id))
    return 0;

  sql ("INSERT into host_identifiers"
       " (uuid, host, owner, name, comment, value, source_type, source_id,"
       "  source_data, creation_time, modification_time)"
       " VALUES"
       " (make_uuid (), %llu, (SELECT id FROM users WHERE uuid = '%s'), '%s',"
       "  '', '%s', '%s', '%s', '', m_now (), m_now ());",
       host,
       current_credentials.uuid,
       quoted_identifier_type,
       quoted_identifier_value,
       quoted_source_type,
       quoted_source_id);

  sql ("UPDATE hosts SET modification_time = (SELECT modification_time"
       "                                      FROM host_identifiers"
       "                                      WHERE id = %llu)"
       " WHERE id = %llu;",
       sql_last_insert_id (),
       host);

  g_free (quoted_identifier_type);
  g_free (quoted_identifier_value);
  g_free (quoted_source_id);
  g_free (quoted_source_type);

  return host;
}

/**
 * @brief Add a report host.
 *
 * @param[in]  report   UUID of resource.
 * @param[in]  host     Host.
 * @param[in]  start    Start time.
 * @param[in]  end      End time.
 *
 * @return Report host.
 */
report_host_t
manage_report_host_add (report_t report, const char *host, time_t start,
                        time_t end)
{
  char *quoted_host = sql_quote (host);
  resource_t report_host;

  sql ("INSERT INTO report_hosts"
       " (report, host, start_time, end_time, current_port, max_port)"
       " SELECT %llu, '%s', %lld, %lld, 0, 0"
       " WHERE NOT EXISTS (SELECT 1 FROM report_hosts WHERE report = %llu"
       "                   AND host = '%s');",
       report, quoted_host, (long long) start, (long long) end, report,
       quoted_host);
  report_host = sql_int64_0 ("SELECT id FROM report_hosts"
                             " WHERE report = %llu AND host = '%s';",
                             report, quoted_host);
  g_free (quoted_host);
  return report_host;
}


/**
 * @brief Counts.
 *
 * @param[in]  report_host  Report host.
 *
 * @return 1 if the host is marked as dead, 0 otherwise.
 */
static int
report_host_result_count (report_host_t report_host)
{
  return sql_int ("SELECT count(*) FROM report_hosts, results"
                  " WHERE report_hosts.id = %llu"
                  "   AND results.report = report_hosts.report"
                  "   AND report_hosts.host = results.host;",
                  report_host);
}

/**
 * @brief Set end time of a report host.
 *
 * @param[in]  report_host  Report host.
 * @param[in]  end_time     End time.
 */
void
report_host_set_end_time (report_host_t report_host, time_t end_time)
{
  sql ("UPDATE report_hosts SET end_time = %lld WHERE id = %llu;",
       end_time, report_host);
}

/**
 * @brief Return whether a host-detail name should be recorded
 *        for snapshot usage.
 *
 * @param[in] name  Host detail name (e.g. "hostname", "MAC").
 *
 * @return TRUE if the identifier should be added to scan_* arrays,
 *         FALSE otherwise.
 */
static gboolean
check_snapshot_identifier_name (const gchar *name)
{
  return name
         && (strcmp (name, "hostname") == 0
             || strcmp (name, "MAC") == 0);
}

/**
 * @brief Add a single host identifier record to the given identifier arrays.
 *
 * @param[in,out] ids         Pointer to identifier array, created if NULL.
 * @param[in,out] hosts       Pointer to host IP array, created if NULL.
 * @param[in]     ip          Host IP address.
 * @param[in]     name        Identifier name (e.g. "hostname", "MAC", "OS").
 * @param[in]     value       Identifier value.
 * @param[in]     source_id   Identifier source id.
 * @param[in]     source_type Identifier source type label.
 * @param[in]     source_data Identifier source data label.
 */
static void
add_host_identifier_to_arrays (array_t **ids, array_t **hosts,
                               const gchar *ip,
                               const gchar *name,
                               const gchar *value,
                               const gchar *source_id,
                               const gchar *source_type,
                               const gchar *source_data)
{
  identifier_t *identifier;

  if (!ip || !*ip || !name || !*name || !value || !*value)
    return;

  if (*ids == NULL)
    *ids = make_array ();
  if (*hosts == NULL)
    *hosts = make_array ();

  identifier = g_malloc (sizeof (*identifier));
  identifier->ip = g_strdup (ip);
  identifier->name = g_strdup (name);
  identifier->value = g_strdup (value);
  identifier->source_id = g_strdup (source_id);
  identifier->source_type = g_strdup (source_type);
  identifier->source_data = g_strdup (source_data);

  array_add (*ids, identifier);
  array_add_new_string (*hosts, g_strdup (ip));
}

/**
 * @brief Add a report host identifier into "snapshot" arrays
 *        and/or legacy arrays.
 *
 * @param[in] ip            Host IP address.
 * @param[in] name          Identifier name.
 * @param[in] value         Identifier value.
 * @param[in] report_uuid   UUID of the report (used as source_id).
 * @param[in] source_name   Name of the identifier source (used as source_data).
 */
void
asset_snapshot_add_report_host_identifier (const gchar *ip,
                                           const gchar *name,
                                           const gchar *value,
                                           const gchar *report_uuid,
                                           const gchar *source_name)
{
  if (check_snapshot_identifier_name (name))
    /* These are freed by asset_snapshots_insert_target
     *  or asset_snapshots_target. */
    add_host_identifier_to_arrays (&snapshot_identifiers,
                                   &snapshot_identifier_hosts,
                                   ip, name, value,
                                   report_uuid,
                                   "Report Host Detail",
                                   source_name);
}

/**
 * @brief Add host details to a report host.
 *
 * @param[in]  report  UUID of resource.
 * @param[in]  ip      Host.
 * @param[in]  entity  XML entity containing details.
 * @param[in]  hashed_host_details  A GHashtable containing hashed host details.
 *
 * @return 0 success, -1 failed to parse XML.
 */
static int
manage_report_host_details (report_t report, const char *ip,
                            entity_t entity, GHashTable *hashed_host_details)
{
  int in_assets;
  entities_t details;
  entity_t detail;
  char *uuid;
  char *hash_value;

  in_assets = sql_int ("SELECT not(value = 'no') FROM task_preferences"
                       " WHERE task = (SELECT task FROM reports"
                       "                WHERE id = %llu)"
                       " AND name = 'in_assets';",
                       report);

  details = entity->entities;
  if (identifiers == NULL)
    identifiers = make_array ();
  if (identifier_hosts == NULL)
    identifier_hosts = make_array ();
  uuid = report_uuid (report);
  while ((detail = first_entity (details)))
    {
      if (strcmp (entity_name (detail), "detail") == 0)
        {
          entity_t source, source_type, source_name, source_desc, name, value;

          /* Parse host detail and add to report */
          source = entity_child (detail, "source");
          if (source == NULL)
            goto error;
          source_type = entity_child (source, "type");
          if (source_type == NULL)
            goto error;
          source_name = entity_child (source, "name");
          if (source_name == NULL)
            goto error;
          source_desc = entity_child (source, "description");
          if (source_desc == NULL)
            goto error;
          name = entity_child (detail, "name");
          if (name == NULL)
            goto error;
          value = entity_child (detail, "value");
          if (value == NULL)
            goto error;

          /* Always collect snapshot identifiers. */
          asset_snapshot_add_report_host_identifier (
            ip,
            entity_text (name),
            entity_text (value),
            uuid,
            entity_text (source_name));

          if (!check_host_detail_exists (report, ip, entity_text (source_type),
                                         entity_text (source_name),
                                         entity_text (source_desc),
                                         entity_text (name),
                                         entity_text (value),
                                         (char**) &hash_value,
                                         hashed_host_details))
            {
              insert_report_host_detail
               (report, ip, entity_text (source_type), entity_text (source_name),
                entity_text (source_desc), entity_text (name), entity_text (value),
                hash_value);
              g_free (hash_value);
            }
          else
            {
              g_free (hash_value);
              details = next_entities (details);
              continue;
            }

          /* Only add to assets if "Add to Assets" is set on the task. */
          if (in_assets)
            {
              if (strcmp (entity_text (name), "hostname") == 0)
                {
                  identifier_t *identifier;

                  identifier = g_malloc (sizeof (identifier_t));
                  identifier->ip = g_strdup (ip);
                  identifier->name = g_strdup ("hostname");
                  identifier->value = g_strdup (entity_text (value));
                  identifier->source_id = g_strdup (uuid);
                  identifier->source_type = g_strdup ("Report Host Detail");
                  identifier->source_data
                    = g_strdup (entity_text (source_name));
                  array_add (identifiers, identifier);
                  array_add_new_string (identifier_hosts, g_strdup (ip));
                }
              if (strcmp (entity_text (name), "MAC") == 0)
                {
                  identifier_t *identifier;

                  identifier = g_malloc (sizeof (identifier_t));
                  identifier->ip = g_strdup (ip);
                  identifier->name = g_strdup ("MAC");
                  identifier->value = g_strdup (entity_text (value));
                  identifier->source_id = g_strdup (uuid);
                  identifier->source_type = g_strdup ("Report Host Detail");
                  identifier->source_data
                    = g_strdup (entity_text (source_name));
                  array_add (identifiers, identifier);
                  array_add_new_string (identifier_hosts, g_strdup (ip));
                }
              if (strcmp (entity_text (name), "OS") == 0
                  && g_str_has_prefix (entity_text (value), "cpe:"))
                {
                  identifier_t *identifier;

                  identifier = g_malloc (sizeof (identifier_t));
                  identifier->ip = g_strdup (ip);
                  identifier->name = g_strdup ("OS");
                  identifier->value = g_strdup (entity_text (value));
                  identifier->source_id = g_strdup (uuid);
                  identifier->source_type = g_strdup ("Report Host Detail");
                  identifier->source_data
                    = g_strdup (entity_text (source_name));
                  array_add (identifiers, identifier);
                  array_add_new_string (identifier_hosts, g_strdup (ip));
                }
              if (strcmp (entity_text (name), "ssh-key") == 0)
                {
                  identifier_t *identifier;

                  identifier = g_malloc (sizeof (identifier_t));
                  identifier->ip = g_strdup (ip);
                  identifier->name = g_strdup ("ssh-key");
                  identifier->value = g_strdup (entity_text (value));
                  identifier->source_id = g_strdup (uuid);
                  identifier->source_type = g_strdup ("Report Host Detail");
                  identifier->source_data
                    = g_strdup (entity_text (source_name));
                  array_add (identifiers, identifier);
                  array_add_new_string (identifier_hosts, g_strdup (ip));
                }
            }
        }
      details = next_entities (details);
    }
  g_free (uuid);

  return 0;

 error:
  g_free (uuid);
  return -1;
}

/**
 * @brief Add a host detail to a report host.
 *
 * @param[in]  report  UUID of resource.
 * @param[in]  host    Host.
 * @param[in]  xml     Report host detail XML.
 * @param[in]  hashed_host_details  A GHashtable containing hashed host details.
 *
 * @return 0 success, -1 failed to parse XML, -2 host was NULL.
 */
int
manage_report_host_detail (report_t report, const char *host,
                           const char *xml, GHashTable *hashed_host_details)
{
  int ret;
  entity_t entity;

  if (host == NULL)
    return -2;

  entity = NULL;
  if (parse_entity (xml, &entity))
    return -1;

  ret = manage_report_host_details (report,
                                    host,
                                    entity,
                                    hashed_host_details);
  free_entity (entity);
  return ret;
}

/**
 * @brief Create a host asset.
 *
 * @param[in]  host_name    Host Name.
 * @param[in]  comment      Comment.
 * @param[out] host_return  Created asset.
 *
 * @return 0 success, 1 failed to find report, 2 host not an IP address,
 *         99 permission denied, -1 error.
 */
int
create_asset_host (const char *host_name, const char *comment,
                   resource_t* host_return)
{
  int host_type;
  resource_t host;
  gchar *quoted_host_name, *quoted_comment;

  if (host_name == NULL)
    return -1;

  sql_begin_immediate ();

  if (acl_user_may ("create_asset") == 0)
    {
      sql_rollback ();
      return 99;
    }

  host_type = gvm_get_host_type (host_name);
  if (host_type != HOST_TYPE_IPV4 && host_type != HOST_TYPE_IPV6)
    {
      sql_rollback ();
      return 2;
    }

  quoted_host_name = sql_quote (host_name);
  quoted_comment = sql_quote (comment ? comment : "");
  sql ("INSERT into hosts"
       " (uuid, owner, name, comment, creation_time, modification_time)"
       " VALUES"
       " (make_uuid (), (SELECT id FROM users WHERE uuid = '%s'), '%s', '%s',"
       "  m_now (), m_now ());",
       current_credentials.uuid,
       quoted_host_name,
       quoted_comment);
  g_free (quoted_comment);

  host = sql_last_insert_id ();

  sql ("INSERT into host_identifiers"
       " (uuid, host, owner, name, comment, value, source_type, source_id,"
       "  source_data, creation_time, modification_time)"
       " VALUES"
       " (make_uuid (), %llu, (SELECT id FROM users WHERE uuid = '%s'), 'ip',"
       "  '', '%s', 'User', '%s', '', m_now (), m_now ());",
       host,
       current_credentials.uuid,
       quoted_host_name,
       current_credentials.uuid);

  g_free (quoted_host_name);

  if (host_return)
    *host_return = host;

  sql_commit ();

  return 0;
}

/**
 * @brief Check whether a string is an identifier name.
 *
 * @param[in]  name  Possible identifier name.
 *
 * @return 1 if an identifier name, else 0.
 */
static int
identifier_name (const char *name)
{
  return (strcmp ("hostname", name) == 0)
         || (strcmp ("MAC", name) == 0)
         || (strcmp ("OS", name) == 0)
         || (strcmp ("ssh-key", name) == 0);
}

/**
 * @brief Create all available assets from a report.
 *
 * @param[in]  report_id  UUID of report.
 * @param[in]  term       Filter term, for min_qod and apply_overrides.
 *
 * @return 0 success, 1 failed to find report, 99 permission denied, -1 error.
 */
int
create_asset_report (const char *report_id, const char *term)
{
  resource_t report;
  iterator_t hosts;
  gchar *quoted_report_id;
  int apply_overrides, min_qod;

  if (report_id == NULL)
    return -1;

  sql_begin_immediate ();

  if (acl_user_may ("create_asset") == 0)
    {
      sql_rollback ();
      return 99;
    }

  report = 0;
  if (find_report_with_permission (report_id, &report, "get_reports"))
    {
      sql_rollback ();
      return -1;
    }

  if (report == 0)
    {
      sql_rollback ();
      return 1;
    }

  /* These are freed by hosts_set_identifiers. */
  if (identifiers == NULL)
    identifiers = make_array ();
  if (identifier_hosts == NULL)
    identifier_hosts = make_array ();

  quoted_report_id = sql_quote (report_id);
  sql ("DELETE FROM host_identifiers WHERE source_id = '%s';",
       quoted_report_id);
  sql ("DELETE FROM host_oss WHERE source_id = '%s';",
       quoted_report_id);
  sql ("DELETE FROM host_max_severities WHERE source_id = '%s';",
       quoted_report_id);
  sql ("DELETE FROM host_details WHERE source_id = '%s';",
       quoted_report_id);
  g_free (quoted_report_id);

  init_report_host_iterator (&hosts, report, NULL, 0);
  while (next (&hosts))
    {
      const char *host;
      report_host_t report_host;
      iterator_t details;

      host = host_iterator_host (&hosts);
      report_host = host_iterator_report_host (&hosts);

      if (report_host_dead (report_host)
          || report_host_result_count (report_host) == 0)
        continue;

      host_notice (host, "ip", host, "Report Host", report_id, 0, 0);

      init_report_host_details_iterator (&details, report_host);
      while (next (&details))
        {
          const char *name;

          name = report_host_details_iterator_name (&details);

          if (identifier_name (name))
            {
              const char *value;
              identifier_t *identifier;

              value = report_host_details_iterator_value (&details);

              if ((strcmp (name, "OS") == 0)
                  && (g_str_has_prefix (value, "cpe:") == 0))
                continue;

              identifier = g_malloc (sizeof (identifier_t));
              identifier->ip = g_strdup (host);
              identifier->name = g_strdup (name);
              identifier->value = g_strdup (value);
              identifier->source_id = g_strdup (report_id);
              identifier->source_type = g_strdup ("Report Host Detail");
              identifier->source_data
               = g_strdup (report_host_details_iterator_source_name (&details));

              array_add (identifiers, identifier);
              array_add_new_string (identifier_hosts, g_strdup (host));
            }
        }
      cleanup_iterator (&details);
    }
  cleanup_iterator (&hosts);
  hosts_set_identifiers (report);
  apply_overrides = filter_term_apply_overrides (term);
  min_qod = filter_term_min_qod (term);
  hosts_set_max_severity (report, &apply_overrides, &min_qod);
  hosts_set_details (report);

  sql_commit ();

  return 0;
}

/**
 * @brief Collect asset snapshot host identifiers from a report.
 *
 * @param[in] report_id  Report UUID string.
 *
 * @return 0 on success, 1 if report not found, 99 permission denied,
 *         -1 on error.
 */
int
asset_snapshot_collect_report_identifiers (const char *report_id)
{
  resource_t r = 0;
  iterator_t hosts;

  if (!report_id)
    return -1;

  sql_begin_immediate ();

  if (acl_user_may ("get_reports") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (find_report_with_permission (report_id, &r, "get_reports"))
    {
      sql_rollback ();
      return -1;
    }

  if (r == 0)
    {
      sql_rollback ();
      return 1;
    }

  /* Iterate report hosts and their host details from DB. */
  init_report_host_iterator (&hosts, r, NULL, 0);
  while (next (&hosts))
    {
      const char *host;
      report_host_t report_host;
      iterator_t details;

      host = host_iterator_host (&hosts);
      report_host = host_iterator_report_host (&hosts);

      if (report_host_dead (report_host)
          || report_host_result_count (report_host) == 0)
        continue;

      init_report_host_details_iterator (&details, report_host);
      while (next (&details))
        {
          const char *name = report_host_details_iterator_name (&details);
          const char *value = report_host_details_iterator_value (&details);
          const char *src_name = report_host_details_iterator_source_name (&details);

          /* Fills snapshot_* . */
          asset_snapshot_add_report_host_identifier (
            host,
            name,
            value,
            report_id,
            src_name);
        }
      cleanup_iterator (&details);
    }
  cleanup_iterator (&hosts);

  sql_commit ();

  return 0;
}

/**
 * @brief Free an identifier.
 *
 * @param[in]  identifier  Identifier.
 */
static void
identifier_free (identifier_t *identifier)
{
  if (identifier)
    {
      g_free (identifier->ip);
      g_free (identifier->name);
      g_free (identifier->value);
      g_free (identifier->source_type);
      g_free (identifier->source_id);
      g_free (identifier->source_data);
    }
}

/**
 * @brief Initialize iterator for asset_snapshots filtered by task/report.
 *
 * @param[out] iterator          Iterator to initialize.
 * @param[in]  task              Filter by task_id (0 means "any task").
 * @param[in]  report            Filter by report_id (0 means "any report").
 * @param[in]  only_missing_key  If true, only rows with asset_key IS NULL.
 */
static void
init_asset_snapshot_iterator (iterator_t *iterator,
                              task_t task,
                              report_t report,
                              gboolean only_missing_key)
{
  g_return_if_fail (iterator);

  GString *where = g_string_new (" WHERE 1=1");

  if (task)
    g_string_append_printf (where, " AND task_id = %llu", task);

  if (report)
    g_string_append_printf (where, " AND report_id = %llu", report);

  if (only_missing_key)
    g_string_append (where, " AND asset_key IS NULL");

  gchar *query = g_strdup_printf (
    "SELECT id, uuid, task_id, report_id, asset_type,"
    "       ip_address, hostname, mac_address, agent_id,"
    "       container_digest, asset_key, creation_time, modification_time"
    "  FROM asset_snapshots"
    "%s"
    " ORDER BY id ASC;",
    where->str);

  init_iterator (iterator, "%s", query);

  g_free (query);
  g_string_free (where, TRUE);
}

/**
 * @brief Return the current asset snapshot ID from an iterator row.
 *
 * @param it Iterator positioned on an asset_snapshot row.
 *
 * @return Asset snapshot ID, or 0 if @p it is done.
 */
static asset_snapshot_t
asset_snapshot_iterator_id (iterator_t *it)
{
  if (it->done) return 0;
  return iterator_int64 (it, AS_COL_ID);
}

/** @brief Get the asset snapshot UUID from the current iterator row. */
DEF_ACCESS (asset_snapshot_iterator_uuid, AS_COL_UUID)

/** @brief Get the IP address from the current iterator row. */
DEF_ACCESS (asset_snapshot_iterator_ip_address, AS_COL_IP_ADDRESS);

/** @brief Get the hostname from the current iterator row. */
DEF_ACCESS (asset_snapshot_iterator_hostname, AS_COL_HOSTNAME);

/** @brief Get the MAC address from the current iterator row. */
DEF_ACCESS (asset_snapshot_iterator_mac_address, AS_COL_MAC_ADDRESS);

/** @brief Get the agent ID from the current iterator row. */
DEF_ACCESS (asset_snapshot_iterator_agent_id, AS_COL_AGENT_ID);

/** @brief Get the container digest from the current iterator row. */
DEF_ACCESS (asset_snapshot_iterator_container_digest, AS_COL_CONTAINER_DIGEST);

/** @brief Get the asset key from the current iterator row. */
DEF_ACCESS (asset_snapshot_iterator_asset_key, AS_COL_ASSET_KEY);

/**
 * @brief Get most recent asset_key for a given MAC address.
 *
 * @param[in] mac  MAC address string.
 *
 * @return Newly allocated asset_key string, or NULL if none found / input empty.
 */
static gchar *
get_asset_key_by_mac (const gchar *mac)
{
  if (!mac || !*mac)
    return NULL;

  return sql_string_ps (
    "SELECT asset_key FROM asset_snapshots"
    " WHERE mac_address = $1"
    "   AND asset_key IS NOT NULL"
    " ORDER BY modification_time DESC LIMIT 1;",
    SQL_STR_PARAM (mac), NULL);
}

/**
* @brief Get most recent asset_key for a given hostname.
 *
 * @param[in] hostname  Hostname string.
 *
 * @return Newly allocated asset_key string, or NULL if none found / input empty.
 */
static gchar *
get_asset_key_by_hostname (const gchar *hostname)
{
  if (!hostname || !*hostname)
    return NULL;

  return sql_string_ps (
    "SELECT asset_key FROM asset_snapshots"
    " WHERE hostname = $1"
    "   AND asset_key IS NOT NULL"
    " ORDER BY modification_time DESC LIMIT 1;",
    SQL_STR_PARAM (hostname), NULL);
}

/**
* @brief Get most recent asset_key for a given IP address.
 *
 * @param[in] ip  IP address string.
 *
 * @return Newly allocated asset_key string, or NULL if none found / input empty.
 */
static gchar *
get_asset_key_by_ip (const gchar *ip)
{
  if (!ip || !*ip)
    return NULL;

  return sql_string_ps (
    "SELECT asset_key FROM asset_snapshots"
    " WHERE ip_address = $1"
    "   AND asset_key IS NOT NULL"
    " ORDER BY modification_time DESC LIMIT 1;",
    SQL_STR_PARAM (ip), NULL);
}

/**
 * @brief Set asset_key for asset_snapshots rows of a report.
 *
 * Priority:
 *   1) MAC address: same MAC use same asset_key
 *   2) Hostname:    same hostname use same asset_key (even across IPs)
 *   3) IP:     if hostname/mac missing, reuse most recent key for that IP
 *
 * @param[in] report  Report the snapshot rows belong to (0 means any report).
 * @param[in] task    Task the snapshot rows belong to (0 means any task).
 */
static void
asset_snapshots_set_asset_keys (report_t report, task_t task)
{
  iterator_t it;

  /* iterate only rows that still need a key */
  init_asset_snapshot_iterator (&it, task, report, TRUE);

  while (next (&it))
    {
      asset_snapshot_t row_id = asset_snapshot_iterator_id (&it);
      const char *ip = asset_snapshot_iterator_ip_address (&it);
      const char *hostname = asset_snapshot_iterator_hostname (&it);
      const char *mac = asset_snapshot_iterator_mac_address (&it);

      gchar *asset_key = NULL;

      /** TODO: 16.12.2025 ozgen - Update this merge algorithm
       *                           once the final approach is defined.
       */
      /* MAC */
      if (mac && *mac)
        asset_key = get_asset_key_by_mac (mac);

      /* Hostname */
      if ((asset_key == NULL || *asset_key == '\0') && hostname && *hostname)
        {
          g_free (asset_key);
          asset_key = get_asset_key_by_hostname (hostname);
        }

      /* IP fallback */
      if ((asset_key == NULL || *asset_key == '\0')
          && ip && *ip
          && (!hostname || !*hostname)
          && (!mac || !*mac))
        {
          g_free (asset_key);
          asset_key = get_asset_key_by_ip (ip);
        }

      if (asset_key && *asset_key)
        {
          sql_ps ("UPDATE asset_snapshots"
                  "   SET asset_key = $1,"
                  "       modification_time = m_now()"
                  " WHERE id = $2;",
                  SQL_STR_PARAM (asset_key),
                  SQL_RESOURCE_PARAM (row_id), NULL);
        }
      else
        {
          /* no match found anywhere, create new stable key */
          sql_ps ("UPDATE asset_snapshots"
                  "   SET asset_key = make_uuid(),"
                  "       modification_time = m_now()"
                  " WHERE id = $1;",
                  SQL_RESOURCE_PARAM (row_id), NULL);
        }

      g_free (asset_key);
    }

  cleanup_iterator (&it);
}

/**
 * @brief Insert one asset snapshot per host from snapshot host identifiers.
 *
 * @param[in]  report     Report that the host identifiers come from.
 * @param[in]  task       Task that produced the report.
 */
static void
asset_snapshots_insert_target (report_t report, task_t task)
{
  if (!snapshot_identifier_hosts || snapshot_identifier_hosts->len == 0)
    {
      g_debug (
        "%s: skip: snapshot_identifier_hosts empty (task=%llu report=%llu)",
        __func__, task, report);
      goto cleanup;
    }

  GHashTable *seen = g_hash_table_new_full (g_str_hash, g_str_equal,
                                            g_free, NULL);

  for (guint host_index = 0;
       snapshot_identifier_hosts && host_index < snapshot_identifier_hosts->len;
       host_index++)
    {
      const gchar *ip = g_ptr_array_index (snapshot_identifier_hosts, host_index);
      if (!ip || !*ip)
          continue;

      if (report_host_noticeable (report, ip) == 0)
          continue;

      if (g_hash_table_contains (seen, ip))
          continue;

      g_hash_table_add (seen, g_strdup (ip));

      const gchar *hostname = NULL;
      const gchar *mac = NULL;

      if (snapshot_identifiers && snapshot_identifiers->len > 0)
        {
          for (guint i = 0; i < snapshot_identifiers->len; i++)
            {
              identifier_t *id = g_ptr_array_index (snapshot_identifiers, i);
              if (!id || !id->ip || g_strcmp0 (id->ip, ip) != 0)
                continue;

              if (id->name && id->value && strcmp (id->name, "hostname") == 0)
                hostname = id->value;
              else if (id->name && id->value && strcmp (id->name, "MAC") == 0)
                mac = id->value;

              if (hostname && mac)
                break;
            }
        }

      sql_ps ("INSERT INTO asset_snapshots"
              " (uuid, task_id, report_id, asset_type,"
              "  ip_address, hostname, mac_address,"
              "  creation_time, modification_time)"
              " VALUES"
              " (make_uuid (), $1, $2, $3, $4, $5, $6, m_now (), m_now ());",
              SQL_RESOURCE_PARAM (task), SQL_RESOURCE_PARAM (report),
              SQL_INT_PARAM (ASSET_TYPE_TARGET),
              SQL_STR_PARAM (ip), SQL_STR_PARAM (hostname),
              SQL_STR_PARAM (mac), NULL);
    }

  g_hash_table_destroy (seen);

cleanup:
  /* Consume snapshot arrays: terminate then free. */
  if (snapshot_identifiers)
    {
      array_terminate (snapshot_identifiers);
      snapshot_identifiers = NULL;
    }
  if (snapshot_identifier_hosts)
    {
      array_terminate (snapshot_identifier_hosts);
      snapshot_identifier_hosts = NULL;
    }
}

/**
 * @brief Create target asset snapshots for a report, unless it is a discovery scan.
 *
 * @param[in]  report     Report that the host identifiers come from.
 * @param[in]  task       Task that produced the report.
 * @param[in]  discovery  Whether the report is a discovery scan.
 */
void
asset_snapshots_target (report_t report, task_t task, gboolean discovery)
{
  if (discovery)
    {
      g_debug ("%s: Discovery scan assets will not stored for counting",
               __func__);
      /* Terminate and free snapshot arrays. */
      if (snapshot_identifiers)
        {
          array_terminate (snapshot_identifiers);
          snapshot_identifiers = NULL;
        }
      if (snapshot_identifier_hosts)
        {
          array_terminate (snapshot_identifier_hosts);
          snapshot_identifier_hosts = NULL;
        }
      return;
    }
  /* Store asset snapshot without asset_key*/
  asset_snapshots_insert_target (report, task);
  /* Set asset_key for asset_snapshots  */
  asset_snapshots_set_asset_keys (report, task);
}

#if ENABLE_AGENTS
/**
 * @brief Create agent asset snapshots for a completed report.
 *
 * @param[in]  report  Report the snapshot belongs to.
 * @param[in]  task    Task that produced the report.
 * @param[in]  group   Agent group.
 */
void
asset_snapshots_agent (report_t report, task_t task, agent_group_t group)
{
  agent_uuid_list_t agent_uuids;

  agent_uuids = agent_uuid_list_from_group (group);
  if (agent_uuids == NULL || agent_uuids->count <= 0 || agent_uuids->agent_uuids == NULL)
    {
      if (agent_uuids)
        agent_uuid_list_free (agent_uuids);
      return;
    }

  for (int i = 0; i < agent_uuids->count; i++)
    {
      const gchar *agent_uuid = agent_uuids->agent_uuids[i];
      gchar *agent_id = NULL;

      if (agent_uuid == NULL || *agent_uuid == '\0')
        continue;

      agent_id = agent_id_by_uuid (agent_uuid);
      if (agent_id == NULL || *agent_id == '\0')
        {
          g_free (agent_id);
          continue;
        }

      sql_ps ("INSERT INTO asset_snapshots"
              " (uuid, task_id, report_id, asset_type,"
              "  asset_key, agent_id,"
              "  creation_time, modification_time)"
              " VALUES"
              " (make_uuid (), $1, $2, $3, $4, $5, m_now (), m_now ());",
              SQL_RESOURCE_PARAM (task), SQL_RESOURCE_PARAM (report),
              SQL_INT_PARAM (ASSET_TYPE_AGENT),
              SQL_STR_PARAM (agent_uuid), SQL_STR_PARAM (agent_id),
              NULL);

      g_free (agent_id);
    }

  agent_uuid_list_free (agent_uuids);
}
#endif /* ENABLE_AGENTS */

#if ENABLE_CONTAINER_SCANNING
/**
 * @brief Insert one asset snapshot per container digest from report hosts.
 *
 * @param[in] report  Report the snapshot belongs to.
 * @param[in] task    Task that produced the report.
 */
static void
asset_snapshots_insert_container_image (report_t report, task_t task)
{
  iterator_t hosts;

  GHashTable *seen = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

  /* Iterate report hosts (host value contains digest for container-image scan) */
  init_report_host_iterator (&hosts, report, NULL, 0);
  while (next (&hosts))
    {
      const char *digest;
      digest = host_iterator_host (&hosts);

      if (!digest || !*digest)
        continue;

      if (g_hash_table_contains (seen, digest))
        continue;

      g_hash_table_add (seen, g_strdup (digest));

      sql_ps ("INSERT INTO asset_snapshots"
              " (uuid, task_id, report_id, asset_type,"
              "  container_digest,"
              "  creation_time, modification_time)"
              " VALUES"
              " (make_uuid (), $1, $2, $3, $4, m_now (), m_now ());",
              SQL_RESOURCE_PARAM (task), SQL_RESOURCE_PARAM (report),
              SQL_INT_PARAM (ASSET_TYPE_CONTAINER_IMAGE),
              SQL_STR_PARAM (digest), NULL);
    }

  cleanup_iterator (&hosts);
  g_hash_table_destroy (seen);
}

/**
 * @brief Lookup most recent asset_key for a given container digest.
 *
 * @param[in] digest  Container digest.
 *
 * @return Duplicated asset_key string or NULL if not found.
 */
static gchar *
get_asset_key_by_container_digest (const gchar *digest)
{

  if (!digest || !*digest)
    return NULL;

  gchar *key = sql_string_ps (
    "SELECT asset_key FROM asset_snapshots"
    " WHERE container_digest = $1"
    "   AND asset_key IS NOT NULL"
    " ORDER BY modification_time DESC LIMIT 1;",
    SQL_STR_PARAM (digest), NULL);

  return key;
}

/**
 * @brief Set asset_key for container-image asset_snapshots rows.
 *
 * @param[in] report  Report the snapshot rows belong to.
 * @param[in] task    Task the snapshot rows belong to.
 */
static void
asset_snapshots_set_asset_keys_container_image (report_t report, task_t task)
{
  iterator_t it;

  init_asset_snapshot_iterator (&it, task, report, TRUE);

  while (next (&it))
    {
      asset_snapshot_t row_id = asset_snapshot_iterator_id (&it);

      const char *digest = asset_snapshot_iterator_container_digest (&it);

      gchar *asset_key = NULL;

      if (digest && *digest)
        asset_key = get_asset_key_by_container_digest (digest);

      if (asset_key && *asset_key)
        {
          sql_ps ("UPDATE asset_snapshots"
                  "   SET asset_key = $1,"
                  "       modification_time = m_now()"
                  " WHERE id = $2;",
                  SQL_STR_PARAM (asset_key),
                  SQL_RESOURCE_PARAM (row_id),
                  NULL);
        }
      else
        {
          /* no match found anywhere, create new stable key */
          sql_ps ("UPDATE asset_snapshots"
                  "   SET asset_key = make_uuid(),"
                  "       modification_time = m_now()"
                  " WHERE id = $1;",
                  SQL_RESOURCE_PARAM (row_id),
                  NULL);
        }

      g_free (asset_key);
    }

  cleanup_iterator (&it);
}

/**
 * @brief Create container scanning asset snapshots for a completed report.
 *
 * @param[in]  report  Report the snapshot belongs to.
 * @param[in]  task    Task that produced the report.
 */
void
asset_snapshots_container_image (report_t report, task_t task)
{
  asset_snapshots_insert_container_image (report, task);
  asset_snapshots_set_asset_keys_container_image (report, task);
}
#endif /* ENABLE_CONTAINER_SCANNING */

/**
 * @brief Dump the string for Asset Snapshot counts to stdout.
 *
 * @param[in]  log_config  Log configuration.
 * @param[in]  database    Location of manage database.
 *
 * @return 0 success, -1 error, -2 database is too old,
 *         -3 database needs to be initialised from server,
 *         -5 database is too new.
 */
int
manage_dump_asset_snapshot_counts (GSList *log_config,
                                   const db_conn_info_t *database)
{
  int ret;

  int total_count = 0;
  int target_count = 0;
  int agent_count = 0;
  int container_image_count = 0;

  ret = manage_option_setup (log_config, database,
                             0 /* avoid_db_check_inserts */);
  if (ret)
    return ret;

  total_count = sql_int (
    "SELECT COUNT(DISTINCT asset_key) FROM asset_snapshots;");

  target_count = sql_int (
    "SELECT COUNT(DISTINCT asset_key) FROM asset_snapshots"
    " WHERE asset_type = %d;",
    ASSET_TYPE_TARGET);

  agent_count = sql_int (
    "SELECT COUNT(DISTINCT asset_key) FROM asset_snapshots"
    " WHERE asset_type = %d;",
    ASSET_TYPE_AGENT);

  container_image_count = sql_int (
    "SELECT COUNT(DISTINCT asset_key) FROM asset_snapshots"
    " WHERE asset_type = %d;",
    ASSET_TYPE_CONTAINER_IMAGE);

  GString *out = g_string_new (NULL);

  g_string_append (out, "Asset Snapshot Counts (distinct asset_key)\n");
  g_string_append_printf (
    out, "  Total:                     %d\n", total_count);
  g_string_append_printf (
    out, "  Targets (type=%d):          %d\n",
    ASSET_TYPE_TARGET, target_count);
  g_string_append_printf (
    out, "  Agents  (type=%d):          %d\n",
    ASSET_TYPE_AGENT, agent_count);
  g_string_append_printf (
    out, "  Container images (type=%d): %d\n",
    ASSET_TYPE_CONTAINER_IMAGE, container_image_count);

  printf ("%s", out->str);

  g_string_free (out, TRUE);

  manage_option_cleanup ();
  return 0;
}

/**
 * @brief Setup hosts and their identifiers after a scan, from host details.
 *
 * At the end of a scan this revises the decision about which asset host to use
 * for each host that has identifiers.  The rules for this decision are described
 * in \ref asset_rules.  (The initial decision is made by \ref host_notice.)
 *
 * @param[in]  report  Report that the identifiers come from.
 */
void
hosts_set_identifiers (report_t report)
{
  if (identifier_hosts)
    {
      int host_index, index;
      gchar *ip;

      array_terminate (identifiers);
      array_terminate (identifier_hosts);

      host_index = 0;
      while ((ip = (gchar*) g_ptr_array_index (identifier_hosts, host_index)))
        {
          host_t host, host_new;
          gchar *quoted_host_name;
          identifier_t *identifier;
          GString *select;

          if (report_host_noticeable (report, ip) == 0)
            {
              host_index++;
              continue;
            }

          quoted_host_name = sql_quote (ip);

          select = g_string_new ("");

          /* Select the most recent host whose identifiers all match the given
           * identifiers, even if the host has fewer identifiers than given. */

          g_string_append_printf (select,
                                  "SELECT id FROM hosts"
                                  " WHERE name = '%s'"
                                  " AND owner = (SELECT id FROM users"
                                  "              WHERE uuid = '%s')",
                                  quoted_host_name,
                                  current_credentials.uuid);

          index = 0;
          while ((identifier = (identifier_t*) g_ptr_array_index (identifiers, index)))
            {
              gchar *quoted_identifier_name, *quoted_identifier_value;

              if (strcmp (identifier->ip, ip))
                {
                  index++;
                  continue;
                }

              quoted_identifier_name = sql_quote (identifier->name);
              quoted_identifier_value = sql_quote (identifier->value);

              g_string_append_printf (select,
                                      " AND (EXISTS (SELECT * FROM host_identifiers"
                                      "              WHERE host = hosts.id"
                                      "              AND owner = (SELECT id FROM users"
                                      "                           WHERE uuid = '%s')"
                                      "              AND name = '%s'"
                                      "              AND value = '%s')"
                                      "      OR NOT EXISTS (SELECT * FROM host_identifiers"
                                      "                     WHERE host = hosts.id"
                                      "                     AND owner = (SELECT id FROM users"
                                      "                                  WHERE uuid = '%s')"
                                      "                     AND name = '%s'))",
                                      current_credentials.uuid,
                                      quoted_identifier_name,
                                      quoted_identifier_value,
                                      current_credentials.uuid,
                                      quoted_identifier_name);

              g_free (quoted_identifier_name);
              g_free (quoted_identifier_value);

              index++;
            }

          g_string_append_printf (select,
                                  " ORDER BY creation_time DESC LIMIT 1;");

          switch (sql_int64 (&host, select->str))
            {
              case 0:
                break;
              case 1:        /* Too few rows in result of query. */
                host = 0;
                break;
              default:       /* Programming error. */
                assert (0);
              case -1:
                host = 0;
                break;
            }

          g_string_free (select, TRUE);

          if (host == 0)
            {
              /* Add the host. */

              sql ("INSERT into hosts"
                   " (uuid, owner, name, comment, creation_time, modification_time)"
                   " VALUES"
                   " (make_uuid (), (SELECT id FROM users WHERE uuid = '%s'), '%s', '',"
                   "  m_now (), m_now ());",
                   current_credentials.uuid,
                   quoted_host_name);

              host_new = host = sql_last_insert_id ();

              /* Make sure the Report Host identifiers added when the host was
               * first noticed now refer to the new host. */

              sql ("UPDATE host_identifiers SET host = %llu"
                   " WHERE source_id = (SELECT uuid FROM reports"
                   "                    WHERE id = %llu)"
                   " AND name = 'ip'"
                   " AND value = '%s';",
                   host_new,
                   report,
                   quoted_host_name);
            }
          else
            {
              /* Use the existing host. */

              host_new = 0;
            }

          /* Add the host identifiers. */

          index = 0;
          while ((identifier = (identifier_t*) g_ptr_array_index (identifiers,
                                                                  index)))
            {
              gchar *quoted_identifier_name, *quoted_identifier_value;
              gchar *quoted_source_id, *quoted_source_type, *quoted_source_data;

              if (strcmp (identifier->ip, ip))
                {
                  index++;
                  continue;
                }

              quoted_identifier_name = sql_quote (identifier->name);
              quoted_identifier_value = sql_quote (identifier->value);
              quoted_source_id = sql_quote (identifier->source_id);
              quoted_source_data = sql_quote (identifier->source_data);
              quoted_source_type = sql_quote (identifier->source_type);

              if (strcmp (identifier->name, "OS") == 0)
                {
                  resource_t os;

                  switch (sql_int64 (&os,
                                     "SELECT id FROM oss"
                                     " WHERE name = '%s'"
                                     " AND owner = (SELECT id FROM users"
                                     "              WHERE uuid = '%s');",
                                     quoted_identifier_value,
                                     current_credentials.uuid))
                    {
                      case 0:
                        break;
                      default:       /* Programming error. */
                        assert (0);
                      case -1:
                      case 1:        /* Too few rows in result of query. */
                        sql ("INSERT into oss"
                             " (uuid, owner, name, comment, creation_time,"
                             "  modification_time)"
                             " VALUES"
                             " (make_uuid (),"
                             "  (SELECT id FROM users WHERE uuid = '%s'),"
                             "  '%s', '', m_now (), m_now ());",
                             current_credentials.uuid,
                             quoted_identifier_value);
                        os = sql_last_insert_id ();
                        break;
                    }

                  sql ("INSERT into host_oss"
                       " (uuid, host, owner, name, comment, os, source_type,"
                       "  source_id, source_data, creation_time, modification_time)"
                       " VALUES"
                       " (make_uuid (), %llu,"
                       "  (SELECT id FROM users WHERE uuid = '%s'),"
                       "  '%s', '', %llu, '%s', '%s', '%s', m_now (), m_now ());",
                       host,
                       current_credentials.uuid,
                       quoted_identifier_name,
                       os,
                       quoted_source_type,
                       quoted_source_id,
                       quoted_source_data);

                  if (host_new == 0)
                    {
                      sql ("UPDATE hosts"
                           " SET modification_time = (SELECT modification_time"
                           "                          FROM host_oss"
                           "                          WHERE id = %llu)"
                           " WHERE id = %llu;",
                           sql_last_insert_id (),
                           host);

                      sql ("UPDATE oss"
                           " SET modification_time = (SELECT modification_time"
                           "                          FROM host_oss"
                           "                          WHERE id = %llu)"
                           " WHERE id = %llu;",
                           sql_last_insert_id (),
                           os);
                    }
                }
              else
                {
                  sql ("INSERT into host_identifiers"
                       " (uuid, host, owner, name, comment, value, source_type,"
                       "  source_id, source_data, creation_time, modification_time)"
                       " VALUES"
                       " (make_uuid (), %llu,"
                       "  (SELECT id FROM users WHERE uuid = '%s'),"
                       "  '%s', '', '%s', '%s', '%s', '%s', m_now (), m_now ());",
                       host,
                       current_credentials.uuid,
                       quoted_identifier_name,
                       quoted_identifier_value,
                       quoted_source_type,
                       quoted_source_id,
                       quoted_source_data);

                  if (host_new == 0)
                    sql ("UPDATE hosts"
                         " SET modification_time = (SELECT modification_time"
                         "                          FROM host_identifiers"
                         "                          WHERE id = %llu)"
                         " WHERE id = %llu;",
                         sql_last_insert_id (),
                         host);
                }

              g_free (quoted_source_type);
              g_free (quoted_source_id);
              g_free (quoted_source_data);
              g_free (quoted_identifier_name);
              g_free (quoted_identifier_value);

              index++;
            }

          g_free (quoted_host_name);
          host_index++;
        }

      index = 0;
      while (identifiers && (index < identifiers->len))
        identifier_free (g_ptr_array_index (identifiers, index++));
      array_free (identifiers);
      identifiers = NULL;

      array_free (identifier_hosts);
      identifier_hosts = NULL;
    }
}

/**
 * @brief Set the maximum severity of each host in a scan.
 *
 * @param[in]  report         The report associated with the scan.
 * @param[in]  overrides_arg  Whether override should be applied.
 * @param[in]  min_qod_arg    Min QOD to use.
 */
void
hosts_set_max_severity (report_t report, int *overrides_arg, int *min_qod_arg)
{
  gchar *new_severity_sql;
  int dynamic_severity, overrides, min_qod;

  if (overrides_arg)
    overrides = *overrides_arg;
  else
    {
      task_t task;
      /* Get "Assets Apply Overrides" task preference. */
      overrides = 1;
      if (report_task (report, &task) == 0)
        {
          char *value;
          value = task_preference_value (task, "assets_apply_overrides");
          if (value && (strcmp (value, "yes") == 0))
            overrides = 1;
          else
            overrides = 0;
          free (value);
        }
    }

  if (min_qod_arg)
    min_qod = *min_qod_arg;
  else
    {
      task_t task;
      /* Get "Assets Min QOD". */
      min_qod = MIN_QOD_DEFAULT;
      if (report_task (report, &task) == 0)
        {
          char *value;
          value = task_preference_value (task, "assets_min_qod");
          if (value)
            min_qod = atoi (value);
          free (value);
        }
    }

  dynamic_severity = setting_dynamic_severity_int ();
  new_severity_sql = new_severity_clause (overrides, dynamic_severity);

  sql ("INSERT INTO host_max_severities"
       " (host, severity, source_type, source_id, creation_time)"
       " SELECT asset_host,"
       "        coalesce ((SELECT max (%s) FROM results"
       "                   WHERE report = %llu"
       "                   AND qod >= %i"
       "                   AND host = (SELECT name FROM hosts"
       "                               WHERE id = asset_host)),"
       "                  0.0),"
       "        'Report',"
       "        (SELECT uuid FROM reports WHERE id = %llu),"
       "        m_now ()"
       " FROM (SELECT host AS asset_host"
       "       FROM host_identifiers"
       "       WHERE source_id = (SELECT uuid FROM reports WHERE id = %llu))"
       "      AS subquery;",
       new_severity_sql,
       report,
       min_qod,
       report,
       report);

  g_free (new_severity_sql);
}

/**
 * @brief Store certain host details in the assets after a scan.
 *
 * @param[in]  report  The report associated with the scan.
 */
void
hosts_set_details (report_t report)
{
  sql ("INSERT INTO host_details"
       " (detail_source_type, detail_source_name, detail_source_description,"
       "  name, value, source_type, source_id, host)"
       " SELECT source_type,"
       "        source_name,"
       "        source_description,"
       "        name,"
       "        value,"
       "        'Report',"
       "        (SELECT uuid FROM reports WHERE id = %llu),"
       "        (SELECT host"
       "         FROM host_identifiers"
       "         WHERE source_id = (SELECT uuid FROM reports"
       "                            WHERE id = %llu)"
       "         AND (SELECT name FROM hosts WHERE id = host)"
       "             = (SELECT host FROM report_hosts"
       "                WHERE id = report_host_details.report_host)"
       "         LIMIT 1)"
       " FROM report_host_details"
       " WHERE (SELECT report FROM report_hosts"
       "        WHERE id = report_host)"
       "       = %llu"
       /* Only if the task is included in the assets. */
       " AND (SELECT value = 'yes' FROM task_preferences"
       "      WHERE task = (SELECT task FROM reports WHERE id = %llu)"
       "      AND name = 'in_assets')"
       /* Ensure that every report host detail has a corresponding host
        *  in the assets. */
       " AND EXISTS (SELECT *"
       "               FROM host_identifiers"
       "              WHERE source_id = (SELECT uuid FROM reports"
       "                                 WHERE id = %llu)"
       "                AND (SELECT name FROM hosts WHERE id = host)"
       "                      = (SELECT host FROM report_hosts"
       "                         WHERE id = report_host_details.report_host))"
       " AND (name IN ('best_os_cpe', 'best_os_txt', 'traceroute'));",
       report,
       report,
       report,
       report,
       report);
}

/**
 * @brief Initialise a host identifier iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  host        Host.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for type then start.
 */
void
init_host_identifier_iterator (iterator_t* iterator, host_t host,
                               int ascending, const char* sort_field)
{
  assert (current_credentials.uuid);

  if (host)
    init_iterator (iterator,
                   "SELECT id, uuid, name, comment, creation_time,"
                   "       modification_time, creation_time AS created,"
                   "       modification_time AS modified, owner, owner, value,"
                   "       source_type, source_id, source_data,"
                   "       (CASE WHEN source_type LIKE 'Report%%'"
                   "        THEN NOT EXISTS (SELECT * FROM reports"
                   "                         WHERE uuid = source_id)"
                   "        ELSE CAST (0 AS boolean)"
                   "        END),"
                   "       '', ''"
                   " FROM host_identifiers"
                   " WHERE host = %llu"
                   " UNION"
                   " SELECT id, uuid, name, comment, creation_time,"
                   "        modification_time, creation_time AS created,"
                   "        modification_time AS modified, owner, owner,"
                   "        (SELECT name FROM oss WHERE id = os),"
                   "        source_type, source_id, source_data,"
                   "        (CASE WHEN source_type LIKE 'Report%%'"
                   "         THEN NOT EXISTS (SELECT * FROM reports"
                   "                          WHERE uuid = source_id)"
                   "         ELSE CAST (0 AS boolean)"
                   "         END),"
                   "        (SELECT uuid FROM oss WHERE id = os),"
                   "        cpe_title ((SELECT name FROM oss WHERE id = os))"
                   " FROM host_oss"
                   " WHERE host = %llu"
                   " ORDER BY %s %s;",
                   host,
                   host,
                   sort_field ? sort_field : "creation_time",
                   ascending ? "ASC" : "DESC");
  else
    init_iterator (iterator,
                   "SELECT id, uuid, name, comment, creation_time,"
                   "       modification_time, creation_time AS created,"
                   "       modification_time AS modified, owner, owner, value,"
                   "       source_type, source_id, source_data, 0, '', ''"
                   " FROM host_identifiers"
                   " ORDER BY %s %s;",
                   sort_field ? sort_field : "creation_time",
                   ascending ? "ASC" : "DESC");
}

/**
 * @brief Get the value from a host identifier iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The value of the host identifier, or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (host_identifier_iterator_value, GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Get the source type from a host identifier iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The source type of the host identifier, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (host_identifier_iterator_source_type,
            GET_ITERATOR_COLUMN_COUNT + 1);

/**
 * @brief Get the source from a host identifier iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The source of the host identifier, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (host_identifier_iterator_source_id, GET_ITERATOR_COLUMN_COUNT + 2);

/**
 * @brief Get the source data from a host identifier iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The source data of the host identifier, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (host_identifier_iterator_source_data,
            GET_ITERATOR_COLUMN_COUNT + 3);

/**
 * @brief Get the source orphan state from a host identifier iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The source orphan state of the host identifier, or 0 if iteration is
 *         complete. Freed by cleanup_iterator.
 */
int
host_identifier_iterator_source_orphan (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 4);
}

/**
 * @brief Get the OS UUID from a host identifier iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The OS UUID of the host identifier, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (host_identifier_iterator_os_id,
            GET_ITERATOR_COLUMN_COUNT + 5);

/**
 * @brief Get the OS title from a host identifier iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The OS title of the host identifier, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (host_identifier_iterator_os_title,
            GET_ITERATOR_COLUMN_COUNT + 6);

/**
 * @brief Extra WHERE clause for host assets.
 *
 * @param[in]  filter  Filter term.
 *
 * @return WHERE clause.
 */
gchar*
asset_host_extra_where (const char *filter)
{
  gchar *ret, *os_id;

  os_id = filter_term_value (filter, "os_id");

  if (os_id)
    {
      gchar *quoted_os_id = os_id ? sql_quote (os_id) : NULL;
      ret = g_strdup_printf (" AND EXISTS"
                             "  (SELECT * FROM host_oss"
                             "   WHERE os = (SELECT id FROM oss"
                             "                WHERE uuid = '%s')"
                             "     AND host = hosts.id)",
                             quoted_os_id);
      g_free (quoted_os_id);
    }
  else
    ret = g_strdup ("");

  g_free (os_id);

  return ret;
}

/**
 * @brief Initialise a host iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 *
 * @return 0 success, 1 failed to find host, 2 failed to find filter,
 *         -1 error.
 */
int
init_asset_host_iterator (iterator_t *iterator, const get_data_t *get)
{
  static const char *filter_columns[] = HOST_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = HOST_ITERATOR_COLUMNS;
  static column_t where_columns[] = HOST_ITERATOR_WHERE_COLUMNS;

  int ret;
  gchar *filter, *extra_where;

  // Get filter
  if (get->filt_id && strcmp (get->filt_id, FILT_ID_NONE))
    {
      if (get->filter_replacement)
        /* Replace the filter term with one given by the caller.  This is
         * used by GET_REPORTS to use the default filter with any task (when
         * given the special value of -3 in filt_id). */
        filter = g_strdup (get->filter_replacement);
      else
        filter = filter_term (get->filt_id);
      if (filter == NULL)
        {
          return 1;
        }
    }
  else
    filter = NULL;

  extra_where = asset_host_extra_where (filter ? filter : get->filter);

  ret = init_get_iterator2 (iterator,
                            "host",
                            get,
                            /* Columns. */
                            columns,
                            /* Columns for trashcan. */
                            NULL,
                            /* WHERE Columns. */
                            where_columns,
                            /* WHERE Columns for trashcan. */
                            NULL,
                            filter_columns,
                            0,
                            NULL,
                            extra_where,
                            NULL,
                            TRUE,
                            FALSE,
                            NULL);

  g_free (filter);
  g_free (extra_where);
  return ret;
}

/**
 * @brief Get the max severity from an asset host iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The maximum severity of the host, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (asset_host_iterator_severity, GET_ITERATOR_COLUMN_COUNT + 2);

/**
 * @brief Generate the extra_tables string for an OS iterator.
 *
 * @return Newly allocated string.
 */
gchar *
asset_os_iterator_opts_table ()
{
  assert (current_credentials.uuid);

  return g_strdup_printf (", (SELECT"
                          "   (SELECT id FROM users"
                          "    WHERE users.uuid = '%s')"
                          "   AS user_id,"
                          "   'host' AS type)"
                          "  AS opts",
                          current_credentials.uuid);
}

/**
 * @brief Initialise an OS iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 *
 * @return 0 success, 1 failed to find os, 2 failed to find filter,
 *         -1 error.
 */
int
init_asset_os_iterator (iterator_t *iterator, const get_data_t *get)
{
  int ret;
  static const char *filter_columns[] = OS_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = OS_ITERATOR_COLUMNS;
  static column_t where_columns[] = OS_ITERATOR_WHERE_COLUMNS;
  gchar *extra_tables;

  extra_tables = asset_os_iterator_opts_table ();

  ret = init_get_iterator2_with (iterator,
                                 "os",
                                 get,
                                 /* Columns. */
                                 columns,
                                 /* Columns for trashcan. */
                                 NULL,
                                 /* WHERE Columns. */
                                 where_columns,
                                 /* WHERE Columns for trashcan. */
                                 NULL,
                                 filter_columns,
                                 0,
                                 extra_tables,
                                 NULL,
                                 NULL,
                                 TRUE,
                                 FALSE,
                                 NULL,
                                 NULL,
                                 0,
                                 0);

  g_free (extra_tables);

  return ret;
}

/**
 * @brief Get the title from an OS iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The title of the OS, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (asset_os_iterator_title, GET_ITERATOR_COLUMN_COUNT + 2);

/**
 * @brief Get the number of installs from an asset OS iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Number of hosts that have the OS.
 */
int
asset_os_iterator_installs (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 3);
}

/**
 * @brief Get the latest severity from an OS iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The severity of the OS, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (asset_os_iterator_latest_severity, GET_ITERATOR_COLUMN_COUNT + 4);

/**
 * @brief Get the highest severity from an OS iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The severity of the OS, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (asset_os_iterator_highest_severity, GET_ITERATOR_COLUMN_COUNT + 5);

/**
 * @brief Get the average severity from an OS iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The severity of the OS, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (asset_os_iterator_average_severity, GET_ITERATOR_COLUMN_COUNT + 6);

/**
 * @brief Get the number of all installs from an asset OS iterator.
 *
 * This includes hosts where the OS is not the best match.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Number of any hosts that have the OS not only as the best match.
 */
int
asset_os_iterator_all_installs (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 7);
}

/**
 * @brief Initialise an asset host detail iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  host        Host.
 */
void
init_host_detail_iterator (iterator_t* iterator, resource_t host)
{
  assert (host);
  init_iterator (iterator,
                 "SELECT sub.id, name, value, source_type, source_id"
                 " FROM (SELECT max (id) AS id FROM host_details"
                 "       WHERE host = %llu"
                 "       GROUP BY name)"
                 "      AS sub,"
                 "      host_details"
                 " WHERE sub.id = host_details.id"
                 " ORDER BY name ASC;",
                 host);
}

/**
 * @brief Get the name from an asset host detail iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The name of the host detail, or NULL if iteration is
 *         complete.  Freed by cleanup_iterator.
 */
DEF_ACCESS (host_detail_iterator_name, 1);

/**
 * @brief Get the name from an asset host detail iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The name of the host detail, or NULL if iteration is
 *         complete.  Freed by cleanup_iterator.
 */
DEF_ACCESS (host_detail_iterator_value, 2);

/**
 * @brief Get the source type from an asset host detail iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The source type of the host detail, or NULL if iteration is
 *         complete.  Freed by cleanup_iterator.
 */
DEF_ACCESS (host_detail_iterator_source_type, 3);

/**
 * @brief Get the source ID from an asset host detail iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The source ID of the host detail, or NULL if iteration is
 *         complete.  Freed by cleanup_iterator.
 */
DEF_ACCESS (host_detail_iterator_source_id, 4);

/**
 * @brief Initialise an OS host iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  os          OS.
 */
void
init_os_host_iterator (iterator_t* iterator, resource_t os)
{
  assert (os);
  init_iterator (iterator,
                 "SELECT id, uuid, name, comment, creation_time,"
                 "       modification_time, creation_time,"
                 "       modification_time, owner, owner,"
                 "       (SELECT round (CAST (severity AS numeric), 1)"
                 "        FROM host_max_severities"
                 "        WHERE host = hosts.id"
                 "        ORDER by creation_time DESC"
                 "        LIMIT 1)"
                 " FROM hosts"
                 " WHERE id IN (SELECT DISTINCT host FROM host_oss"
                 "              WHERE os = %llu)"
                 " ORDER BY modification_time DESC;",
                 os);
}

/**
 * @brief Get the severity from an OS host detail iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The severity of the OS host, or NULL if iteration is
 *         complete.  Freed by cleanup_iterator.
 */
DEF_ACCESS (os_host_iterator_severity, GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Initialise a host iterator for GET_RESOURCE_NAMES.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 *
 * @return 0 success, 1 failed to find host, 2 failed to find filter,
 *         -1 error.
 */
int
init_resource_names_host_iterator (iterator_t *iterator, get_data_t *get)
{
  static const char *filter_columns[] = { GET_ITERATOR_FILTER_COLUMNS };
  static column_t columns[] = { GET_ITERATOR_COLUMNS (hosts) };
  int ret;

  ret = init_get_iterator2 (iterator,
                            "host",
                            get,
                            /* Columns. */
                            columns,
                            /* Columns for trashcan. */
                            NULL,
                            /* WHERE Columns. */
                            NULL,
                            /* WHERE Columns for trashcan. */
                            NULL,
                            filter_columns,
                            0,
                            NULL,
                            NULL,
                            NULL,
                            TRUE,
                            FALSE,
                            NULL);

  return ret;
}

/**
 * @brief Initialise an OS iterator for GET_RESOURCE_NAMES.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 *
 * @return 0 success, 1 failed to find os, 2 failed to find filter,
 *         -1 error.
 */
int
init_resource_names_os_iterator (iterator_t *iterator, get_data_t *get)
{
  static const char *filter_columns[] = { GET_ITERATOR_FILTER_COLUMNS };
  static column_t columns[] = { GET_ITERATOR_COLUMNS (oss) };
  int ret;

  ret = init_get_iterator2_with (iterator,
                                 "os",
                                 get,
                                 /* Columns. */
                                 columns,
                                 /* Columns for trashcan. */
                                 NULL,
                                 /* WHERE Columns. */
                                 NULL,
                                 /* WHERE Columns for trashcan. */
                                 NULL,
                                 filter_columns,
                                 0,
                                 NULL,
                                 NULL,
                                 NULL,
                                 TRUE,
                                 FALSE,
                                 NULL,
                                 NULL,
                                 0,
                                 0);

  return ret;
}

/**
 * @brief Get the writable status from an asset iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 1 if writable, else 0.
 */
int
asset_iterator_writable (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return iterator_int64 (iterator, GET_ITERATOR_COLUMN_COUNT);
}

/**
 * @brief Get the "in use" status from an asset iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 1 if in use, else 0.
 */
int
asset_iterator_in_use (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return iterator_int64 (iterator, GET_ITERATOR_COLUMN_COUNT + 1);
}

/**
 * @brief Modify an asset.
 *
 * @param[in]   asset_id        UUID of asset.
 * @param[in]   comment         Comment on asset.
 *
 * @return 0 success, 1 failed to find asset, 3 asset_id required,
 *         99 permission denied, -1 internal error.
 */
int
modify_asset (const char *asset_id, const char *comment)
{
  gchar *quoted_asset_id, *quoted_comment;
  resource_t asset;

  if (asset_id == NULL)
    return 3;

  sql_begin_immediate ();

  if (acl_user_may ("modify_asset") == 0)
    {
      sql_rollback ();
      return 99;
    }

  /* Host. */

  quoted_asset_id = sql_quote (asset_id);
  switch (sql_int64 (&asset,
                     "SELECT id FROM hosts WHERE uuid = '%s';",
                     quoted_asset_id))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        asset = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_asset_id);
        sql_rollback ();
        return -1;
        break;
    }

  g_free (quoted_asset_id);

  if (asset == 0)
    {
      sql_rollback ();
      return 1;
    }

  quoted_comment = sql_quote (comment ?: "");

  sql ("UPDATE hosts SET"
       " comment = '%s',"
       " modification_time = m_now ()"
       " WHERE id = %llu;",
       quoted_comment, asset);

  g_free (quoted_comment);

  sql_commit ();

  return 0;
}

/**
 * @brief Find a host for a specific permission, given a UUID.
 *
 * @param[in]   uuid        UUID of host.
 * @param[out]  host      Host return, 0 if successfully failed to find host.
 * @param[in]   permission  Permission.
 *
 * @return FALSE on success (including if failed to find host), TRUE on error.
 */
static gboolean
find_host_with_permission (const char* uuid, host_t* host,
                           const char *permission)
{
  return find_resource_with_permission ("host", uuid, host, permission, 0);
}

/**
 * @brief Delete all asset that came from a report.
 *
 * Assume caller started a transaction.
 *
 * @param[in]  report_id  UUID of report.
 *
 * @return 0 success, 2 failed to find report, 4 UUID
 *         required, 99 permission denied, -1 error.
 */
static int
delete_report_assets (const char *report_id)
{
  resource_t report;
  gchar *quoted_report_id;

  report = 0;
  if (find_report_with_permission (report_id, &report, "delete_report"))
    {
      sql_rollback ();
      return -1;
    }

  if (report == 0)
    {
      sql_rollback ();
      return 1;
    }

  quoted_report_id = sql_quote (report_id);

  /* Delete the hosts and OSs identified by this report if they were only
   * identified by this report. */

  sql ("CREATE TEMPORARY TABLE delete_report_assets_hosts (host INTEGER);");

  /* Collect hosts that were only identified by the given source. */
  sql ("INSERT into delete_report_assets_hosts"
       " (host)"
       " SELECT id FROM hosts"
       " WHERE (EXISTS (SELECT * FROM host_identifiers"
       "                WHERE host = hosts.id"
       "                AND source_id = '%s')"
       "        OR EXISTS (SELECT * FROM host_oss"
       "                   WHERE host = hosts.id"
       "                   AND source_id = '%s'))"
       " AND NOT EXISTS (SELECT * FROM host_identifiers"
       "                 WHERE host = hosts.id"
       "                 AND source_id != '%s')"
       " AND NOT EXISTS (SELECT * FROM host_oss"
       "                 WHERE host = hosts.id"
       "                 AND source_id != '%s');",
      quoted_report_id,
      quoted_report_id,
      quoted_report_id,
      quoted_report_id);

  sql ("DELETE FROM host_identifiers WHERE source_id = '%s';",
       quoted_report_id);
  sql ("DELETE FROM host_oss WHERE source_id = '%s';",
       quoted_report_id);
  sql ("DELETE FROM host_max_severities WHERE source_id = '%s';",
       quoted_report_id);
  sql ("DELETE FROM host_details WHERE source_id = '%s';",
       quoted_report_id);

  g_free (quoted_report_id);

  /* The host may have details from sources that did not identify the host. */
  sql ("DELETE FROM host_details"
       " WHERE host in (SELECT host FROM delete_report_assets_hosts);");

  /* The host may have severities from sources that did not identify the
   * host. */
  sql ("DELETE FROM host_max_severities"
       " WHERE host in (SELECT host FROM delete_report_assets_hosts);");

  sql ("DELETE FROM hosts"
       " WHERE id in (SELECT host FROM delete_report_assets_hosts);");

  sql ("DROP TABLE delete_report_assets_hosts;");

  sql_commit ();
  return 0;
}

/**
 * @brief Delete an asset.
 *
 * @param[in]  asset_id   UUID of asset.
 * @param[in]  report_id  UUID of report from which to delete assets.
 *                        Overridden by asset_id.
 * @param[in]  dummy      Dummy arg to match other delete functions.
 *
 * @return 0 success, 1 asset is in use, 2 failed to find asset, 4 UUID
 *         required, 99 permission denied, -1 error.
 */
int
delete_asset (const char *asset_id, const char *report_id, int dummy)
{
  resource_t asset, parent;
  gchar *quoted_asset_id, *parent_id;

  asset = parent = 0;

  sql_begin_immediate ();

  if (acl_user_may ("delete_asset") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (asset_id == NULL)
    {
      if (report_id == NULL)
        {
          sql_rollback ();
          return 3;
        }
      return delete_report_assets (report_id);
    }

  /* Host identifier. */

  quoted_asset_id = sql_quote (asset_id);
  switch (sql_int64 (&asset,
                     "SELECT id FROM host_identifiers WHERE uuid = '%s';",
                     quoted_asset_id))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        asset = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_asset_id);
        sql_rollback ();
        return -1;
        break;
    }

  g_free (quoted_asset_id);

  if (asset)
    {
      parent_id = sql_string ("SELECT uuid FROM hosts"
                              " WHERE id = (SELECT host FROM host_identifiers"
                              "             WHERE id = %llu);",
                              asset);
      parent = 0;
      if (find_host_with_permission (parent_id, &parent, "delete_asset"))
        {
          sql_rollback ();
          return -1;
        }

      if (parent == 0)
        {
          sql_rollback ();
          return 99;
        }

      sql ("DELETE FROM host_identifiers WHERE id = %llu;", asset);
      sql_commit ();

      return 0;
    }

  /* Host OS. */

  quoted_asset_id = sql_quote (asset_id);
  switch (sql_int64 (&asset,
                     "SELECT id FROM host_oss WHERE uuid = '%s';",
                     quoted_asset_id))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        asset = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_asset_id);
        sql_rollback ();
        return -1;
        break;
    }

  g_free (quoted_asset_id);

  if (asset)
    {
      parent_id = sql_string ("SELECT uuid FROM hosts"
                              " WHERE id = (SELECT host FROM host_oss"
                              "             WHERE id = %llu);",
                              asset);
      parent = 0;
      if (find_host_with_permission (parent_id, &parent, "delete_asset"))
        {
          sql_rollback ();
          return -1;
        }

      if (parent == 0)
        {
          sql_rollback ();
          return 99;
        }

      sql ("DELETE FROM host_oss WHERE id = %llu;", asset);
      sql_commit ();

      return 0;
    }

  /* OS. */

  quoted_asset_id = sql_quote (asset_id);
  switch (sql_int64 (&asset,
                     "SELECT id FROM oss WHERE uuid = '%s';",
                     quoted_asset_id))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        asset = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_asset_id);
        sql_rollback ();
        return -1;
        break;
    }

  g_free (quoted_asset_id);

  if (asset)
    {
      if (sql_int ("SELECT count (*) FROM host_oss"
                   " WHERE os = %llu;",
                   asset))
        {
          sql_rollback ();
          return 1;
        }

      sql ("DELETE FROM oss WHERE id = %llu;", asset);
      permissions_set_orphans ("os", asset, LOCATION_TABLE);
      tags_remove_resource ("os", asset, LOCATION_TABLE);
      sql_commit ();

      return 0;
    }

  /* Host. */

  quoted_asset_id = sql_quote (asset_id);
  switch (sql_int64 (&asset,
                     "SELECT id FROM hosts WHERE uuid = '%s';",
                     quoted_asset_id))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        asset = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_asset_id);
        sql_rollback ();
        return -1;
        break;
    }

  g_free (quoted_asset_id);

  if (asset)
    {
      sql ("DELETE FROM host_identifiers WHERE host = %llu;", asset);
      sql ("DELETE FROM host_oss WHERE host = %llu;", asset);
      sql ("DELETE FROM host_max_severities WHERE host = %llu;", asset);
      sql ("DELETE FROM host_details WHERE host = %llu;", asset);
      sql ("DELETE FROM hosts WHERE id = %llu;", asset);
      permissions_set_orphans ("host", asset, LOCATION_TABLE);
      tags_remove_resource ("host", asset, LOCATION_TABLE);
      sql_commit ();

      return 0;
    }

  sql_rollback ();
  return 2;
}

/**
 * @brief Tests if a report host is marked as dead.
 *
 * @param[in]  report_host  Report host.
 *
 * @return 1 if the host is marked as dead, 0 otherwise.
 */
static int
report_host_dead (report_host_t report_host)
{
  return sql_int ("SELECT count(*) != 0 FROM report_host_details"
                  " WHERE report_host = %llu"
                  "   AND name = 'Host dead'"
                  "   AND value != '0';",
                  report_host);
}

/**
 * @brief Get the IP of a host, using the 'hostname' report host details.
 *
 * The most recent host detail takes preference.
 *
 * @param[in]  host  Host name or IP.
 *
 * @return Newly allocated UUID if available, else NULL.
 */
gchar*
report_host_ip (const char *host)
{
  gchar *quoted_host, *ret;
  quoted_host = sql_quote (host);
  ret = sql_string ("SELECT host FROM report_hosts"
                    " WHERE id = (SELECT report_host FROM report_host_details"
                    "             WHERE name = 'hostname'"
                    "             AND value = '%s'"
                    "             ORDER BY id DESC LIMIT 1);",
                    quoted_host);
  g_free (quoted_host);
  return ret;
}

/**
 * @brief Get the hostname of a report_host.
 *
 * The most recent host detail takes preference.
 *
 * @param[in]  report_host  Report host.
 *
 * @return Newly allocated hostname if available, else NULL.
 */
gchar*
report_host_hostname (report_host_t report_host)
{
  return sql_string ("SELECT value FROM report_host_details"
                     " WHERE report_host = %llu"
                     " AND name = 'hostname'"
                     " ORDER BY id DESC LIMIT 1;",
                     report_host);
}

/**
 * @brief Get the best_os_cpe of a report_host.
 *
 * The most recent host detail takes preference.
 *
 * @param[in]  report_host  Report host.
 *
 * @return Newly allocated best_os_cpe if available, else NULL.
 */
gchar*
report_host_best_os_cpe (report_host_t report_host)
{
  return sql_string ("SELECT value FROM report_host_details"
                     " WHERE report_host = %llu"
                     " AND name = 'best_os_cpe'"
                     " ORDER BY id DESC LIMIT 1;",
                     report_host);
}

/**
 * @brief Get the best_os_txt of a report_host.
 *
 * The most recent host detail takes preference.
 *
 * @param[in]  report_host  Report host.
 *
 * @return Newly allocated best_os_txt if available, else NULL.
 */
gchar*
report_host_best_os_txt (report_host_t report_host)
{
  return sql_string ("SELECT value FROM report_host_details"
                     " WHERE report_host = %llu"
                     " AND name = 'best_os_txt'"
                     " ORDER BY id DESC LIMIT 1;",
                     report_host);
}

/**
 * @brief Check if a report host is alive and has at least one result.
 *
 * @param[in]  report  Report.
 * @param[in]  host    Host name or IP.
 *
 * @return 0 if dead, else alive.
 */
int
report_host_noticeable (report_t report, const gchar *host)
{
  report_host_t report_host = 0;

  sql_int64 (&report_host,
             "SELECT id FROM report_hosts"
             " WHERE report = %llu AND host = '%s';",
             report,
             host);

  return report_host
         && report_host_dead (report_host) == 0
         && report_host_result_count (report_host) > 0;
}

/**
 * @brief Count number of hosts.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of hosts in filtered set.
 */
int
asset_host_count (const get_data_t *get)
{
  static const char *filter_columns[] = HOST_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = HOST_ITERATOR_COLUMNS;
  static column_t where_columns[] = HOST_ITERATOR_WHERE_COLUMNS;
  return count2 ("host", get, columns, NULL, where_columns, NULL,
                 filter_columns, 0, NULL, NULL, NULL, TRUE);
}

/**
 * @brief Count number of oss.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of oss in filtered set.
 */
int
asset_os_count (const get_data_t *get)
{
  static const char *extra_columns[] = OS_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = OS_ITERATOR_COLUMNS;
  static column_t where_columns[] = OS_ITERATOR_WHERE_COLUMNS;
  int ret;

  ret = count2 ("os", get, columns, NULL, where_columns, NULL,
                extra_columns, 0, 0, 0, NULL, TRUE);

  return ret;
}

/**
 * @brief Get XML of a detailed host route.
 *
 * @param[in]  host  The host.
 *
 * @return XML.
 */
gchar*
host_routes_xml (host_t host)
{
  iterator_t routes;
  GString* buffer;

  gchar *owned_clause, *with_clause;

  owned_clause = acl_where_owned_for_get ("host", NULL, NULL, &with_clause);

  buffer = g_string_new ("<routes>");
  init_iterator (&routes,
                 "SELECT outer_details.value,"
                 "       outer_details.source_type,"
                 "       outer_details.source_id,"
                 "       outer_identifiers.modification_time"
                 "  FROM host_details AS outer_details"
                 "  JOIN host_identifiers AS outer_identifiers"
                 "    ON outer_identifiers.host = outer_details.host"
                 " WHERE outer_details.host = %llu"
                 "   AND outer_details.name = 'traceroute'"
                 "   AND outer_details.source_id = outer_identifiers.source_id"
                 "   AND outer_identifiers.name='ip'"
                 "   AND outer_identifiers.modification_time"
                 "         = (SELECT max (modification_time)"
                 "              FROM host_identifiers"
                 "             WHERE host_identifiers.host = %llu"
                 "               AND host_identifiers.source_id IN"
                 "                   (SELECT source_id FROM host_details"
                 "                     WHERE host = %llu"
                 "                       AND value = outer_details.value)"
                 "              AND host_identifiers.name='ip')"
                 " ORDER BY outer_identifiers.modification_time DESC;",
                 host, host, host);

  while (next (&routes))
    {
      const char *traceroute;
      const char *source_id;
      time_t modified;
      gchar **hop_ips, **hop_ip;
      int distance;

      g_string_append (buffer, "<route>");

      traceroute = iterator_string (&routes, 0);
      source_id = iterator_string (&routes, 2);
      modified = iterator_int64 (&routes, 3);

      hop_ips = g_strsplit (traceroute, ",", 0);
      hop_ip = hop_ips;

      distance = 0;

      while (*hop_ip != NULL) {
        iterator_t best_host_iterator;
        const char *best_host_id;
        int same_source;

        init_iterator (&best_host_iterator,
                       "%s"
                       " SELECT hosts.uuid,"
                       "       (source_id='%s')"
                       "         AS same_source"
                       "  FROM hosts, host_identifiers"
                       " WHERE hosts.id = host_identifiers.host"
                       "   AND host_identifiers.name = 'ip'"
                       "   AND host_identifiers.value='%s'"
                       "   AND %s"
                       " ORDER BY same_source DESC,"
                       "          abs(host_identifiers.modification_time"
                       "              - %llu) ASC"
                       " LIMIT 1;",
                       with_clause ? with_clause : "",
                       source_id,
                       *hop_ip,
                       owned_clause,
                       modified);

        if (next (&best_host_iterator))
          {
            best_host_id = iterator_string (&best_host_iterator, 0);
            same_source = iterator_int (&best_host_iterator, 1);
          }
        else
          {
            best_host_id = NULL;
            same_source = 0;
          }

        g_string_append_printf (buffer,
                                "<host id=\"%s\""
                                " distance=\"%d\""
                                " same_source=\"%d\">"
                                "<ip>%s</ip>"
                                "</host>",
                                best_host_id ? best_host_id : "",
                                distance,
                                same_source,
                                *hop_ip);

        cleanup_iterator (&best_host_iterator);

        distance++;
        hop_ip++;
      }

      g_string_append (buffer, "</route>");
      g_strfreev(hop_ips);
    }

  g_free (with_clause);
  g_free (owned_clause);

  cleanup_iterator (&routes);

  g_string_append (buffer, "</routes>");

  return g_string_free (buffer, FALSE);
}

/**
 * @brief Generates and adds assets from report host details
 *
 * @param[in]  report   The report to get host details from.
 * @param[in]  host_ip  IP address of the host to get details from.
 *
 * @return 0 success, -1 error.
 */
int
add_assets_from_host_in_report (report_t report, const char *host_ip)
{
  int ret;
  gchar *quoted_host;
  char *report_id;
  report_host_t report_host = 0;

  /* Get report UUID */
  report_id = report_uuid (report);
  if (report_id == NULL)
    {
      g_warning ("%s: report %llu not found.",
                 __func__, report);
      return -1;
    }

  /* Find report_host */
  quoted_host = sql_quote (host_ip);
  sql_int64 (&report_host,
             "SELECT id FROM report_hosts"
             " WHERE host = '%s' AND report = %llu",
             quoted_host,
             report);
  g_free (quoted_host);
  if (report_host == 0)
    {
      g_warning ("%s: report_host for host '%s' and report '%s' not found.",
                 __func__, host_ip, report_id);
      free (report_id);
      return -1;
    }

  /* Create assets */
  if (report_host_noticeable (report, host_ip))
    {
      host_notice (host_ip, "ip", host_ip, "Report Host", report_id, 1, 1);
    }

  ret = add_tls_certificates_from_report_host (report_host,
                                               report_id,
                                               host_ip);
  if (ret)
    {
      free (report_id);
      return ret;
    }

  return 0;
}
