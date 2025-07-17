/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file manage_resources.c
 * @brief GVM management layer: Generic resource type handling.
 *
 * Non-SQL generic resource type handling code for the GVM management layer.
 */

#include "manage_resources.h"



/* Resource type information. */

/**
 * @brief Check whether a resource type name is valid.
 *
 * @param[in]  type  Type of resource.
 *
 * @return 1 yes, 0 no.
 */
int
valid_type (const char* type)
{

#if ENABLE_AGENTS
  if (strcasecmp (type, "agent") == 0
      || strcasecmp (type, "agent_installer") == 0) 
    return 1;
#endif

  return (strcasecmp (type, "alert") == 0)
         || (strcasecmp (type, "asset") == 0)
         || (strcasecmp (type, "config") == 0)
         || (strcasecmp (type, "credential") == 0)
         || (strcasecmp (type, "filter") == 0)
         || (strcasecmp (type, "group") == 0)
         || (strcasecmp (type, "host") == 0)
         || (strcasecmp (type, "info") == 0)
         || (strcasecmp (type, "note") == 0)
         || (strcasecmp (type, "os") == 0)
         || (strcasecmp (type, "override") == 0)
         || (strcasecmp (type, "permission") == 0)
         || (strcasecmp (type, "port_list") == 0)
         || (strcasecmp (type, "report") == 0)
         || (strcasecmp (type, "report_config") == 0)
         || (strcasecmp (type, "report_format") == 0)
         || (strcasecmp (type, "result") == 0)
         || (strcasecmp (type, "role") == 0)
         || (strcasecmp (type, "scanner") == 0)
         || (strcasecmp (type, "schedule") == 0)
         || (strcasecmp (type, "tag") == 0)
         || (strcasecmp (type, "target") == 0)
         || (strcasecmp (type, "task") == 0)
         || (strcasecmp (type, "ticket") == 0)
         || (strcasecmp (type, "tls_certificate") == 0)
         || (strcasecmp (type, "user") == 0)
         || (strcasecmp (type, "vuln") == 0);
}

/**
 * @brief Check whether a resource subtype name is valid.
 *
 * @param[in]  subtype  Subtype of resource.
 *
 * @return 1 yes, 0 no.
 */
int
valid_subtype (const char* type)
{
    return (strcasecmp (type, "audit_report") == 0)
          || (strcasecmp (type, "audit") == 0)
          || (strcasecmp (type, "policy") == 0);
}

/**
 * @brief Return DB name of type.
 *
 * @param[in]  type  Database or pretty name.
 *
 * @return Database name of type if possible, else NULL.
 */
const char *
type_db_name (const char* type)
{
  if (type == NULL)
    return NULL;

  if (valid_type (type))
    return type;

#if ENABLE_AGENTS
  if (strcasecmp (type, "Agent") == 0)
    return "agent";
  if (strcasecmp (type, "Agent Installer") == 0)
    return "agent_installer";
#endif

  if (strcasecmp (type, "Alert") == 0)
    return "alert";
  if (strcasecmp (type, "Asset") == 0)
    return "asset";
  if (strcasecmp (type, "Config") == 0)
    return "config";
  if (strcasecmp (type, "Credential") == 0)
    return "credential";
  if (strcasecmp (type, "Filter") == 0)
    return "filter";
  if (strcasecmp (type, "Note") == 0)
    return "note";
  if (strcasecmp (type, "Override") == 0)
    return "override";
  if (strcasecmp (type, "Permission") == 0)
    return "permission";
  if (strcasecmp (type, "Port List") == 0)
    return "port_list";
  if (strcasecmp (type, "Report") == 0)
    return "report";
  if (strcasecmp (type, "Report Config") == 0)
    return "report_config";
  if (strcasecmp (type, "Report Format") == 0)
    return "report_format";
  if (strcasecmp (type, "Result") == 0)
    return "result";
  if (strcasecmp (type, "Role") == 0)
    return "role";
  if (strcasecmp (type, "Scanner") == 0)
    return "scanner";
  if (strcasecmp (type, "Schedule") == 0)
    return "schedule";
  if (strcasecmp (type, "Tag") == 0)
    return "tag";
  if (strcasecmp (type, "Target") == 0)
    return "target";
  if (strcasecmp (type, "Task") == 0)
    return "task";
  if (strcasecmp (type, "Ticket") == 0)
    return "ticket";
  if (strcasecmp (type, "TLS Certificate") == 0)
    return "tls_certificate";
  if (strcasecmp (type, "SecInfo") == 0)
    return "info";
  return NULL;
}

/**
 * @brief Check whether a resource type is an asset subtype.
 *
 * @param[in]  type  Type of resource.
 *
 * @return 1 yes, 0 no.
 */
int
type_is_asset_subtype (const char *type)
{
  return (strcasecmp (type, "host")
          && strcasecmp (type, "os"))
         == 0;
}

/**
 * @brief Check whether a resource type is an info subtype.
 *
 * @param[in]  type  Type of resource.
 *
 * @return 1 yes, 0 no.
 */
int
type_is_info_subtype (const char *type)
{
  return (strcasecmp (type, "nvt")
          && strcasecmp (type, "cve")
          && strcasecmp (type, "cpe")
          && strcasecmp (type, "cert_bund_adv")
          && strcasecmp (type, "dfn_cert_adv"))
         == 0;
}

/**
 * @brief Check whether a resource type is a report subtype.
 *
 * @param[in]  type  Type of resource.
 *
 * @return 1 yes, 0 no.
 */
int
type_is_report_subtype (const char *type)
{
  return (strcasecmp (type, "audit_report") == 0);
}

/**
 * @brief Check whether a resource type is a task subtype.
 *
 * @param[in]  type  Type of resource.
 *
 * @return 1 yes, 0 no.
 */
int
type_is_task_subtype (const char *type)
{
  return (strcasecmp (type, "audit") == 0);
}

/**
 * @brief Check whether a resource type is a config subtype.
 *
 * @param[in]  type  Type of resource.
 *
 * @return 1 yes, 0 no.
 */
int
type_is_config_subtype (const char *type)
{
  return (strcasecmp (type, "policy") == 0);
}

/**
 * @brief Check whether a type has a name and comment.
 *
 * @param[in]  type          Type of resource.
 *
 * @return 1 yes, 0 no.
 */
int
type_named (const char *type)
{
  return strcasecmp (type, "note")
         && strcasecmp (type, "override");
}

/**
 * @brief Check whether a type must have globally unique names.
 *
 * @param[in]  type          Type of resource.
 *
 * @return 1 yes, 0 no.
 */
int
type_globally_unique (const char *type)
{
  if (strcasecmp (type, "user") == 0)
    return 1;
  else
    return 0;
}

/**
 * @brief Check whether a type has a comment.
 *
 * @param[in]  type  Type of resource.
 *
 * @return 1 yes, 0 no.
 */
int
type_has_comment (const char *type)
{
  return strcasecmp (type, "report_format");
}

/**
 * @brief Check whether a resource type uses the trashcan.
 *
 * @param[in]  type  Type of resource.
 *
 * @return 1 yes, 0 no.
 */
int
type_has_trash (const char *type)
{
  return strcasecmp (type, "report")
         && strcasecmp (type, "result")
         && strcasecmp (type, "info")
         && type_is_info_subtype (type) == 0
         && strcasecmp (type, "vuln")
         && strcasecmp (type, "user")
         && strcasecmp (type, "tls_certificate");
}

/**
 * @brief Check whether a resource type has an owner.
 *
 * @param[in]  type  Type of resource.
 *
 * @return 1 yes, 0 no.
 */
int
type_owned (const char* type)
{
  return strcasecmp (type, "info")
         && type_is_info_subtype (type) == 0
         && strcasecmp (type, "vuln");
}

/**
 * @brief Check whether the trash is in the real table.
 *
 * @param[in]  type  Type of resource.
 *
 * @return 1 yes, 0 no.
 */
int
type_trash_in_table (const char *type)
{
  return strcasecmp (type, "task") == 0;
}


/* SecInfo specific resource type information. */

/**
 * @brief Return the plural name of a resource type.
 *
 * @param[in]  type  Resource type.
 *
 * @return Plural name of type.
 */
const char *
secinfo_type_name_plural (const char* type)
{
  if (type == NULL)
    return "ERROR";

  if (strcasecmp (type, "cpe") == 0)
    return "CPEs";
  if (strcasecmp (type, "cve") == 0)
    return "CVEs";
  if (strcasecmp (type, "cert_bund_adv") == 0)
    return "CERT-Bund Advisories";
  if (strcasecmp (type, "dfn_cert_adv") == 0)
    return "DFN-CERT Advisories";
  if (strcasecmp (type, "nvt") == 0)
    return "NVTs";

  return "ERROR";
}

/**
 * @brief Return the name of a resource type.
 *
 * @param[in]  type  Resource type.
 *
 * @return Name of type.
 */
const char *
secinfo_type_name (const char* type)
{
  if (type == NULL)
    return "ERROR";

  if (strcasecmp (type, "cpe") == 0)
    return "CPE";
  if (strcasecmp (type, "cve") == 0)
    return "CVE";
  if (strcasecmp (type, "cert_bund_adv") == 0)
    return "CERT-Bund Advisory";
  if (strcasecmp (type, "dfn_cert_adv") == 0)
    return "DFN-CERT Advisory";
  if (strcasecmp (type, "nvt") == 0)
    return "NVT";

  return "ERROR";
}

/**
 * @brief Check if a type is a SCAP type.
 *
 * @param[in]  type  Resource type.
 *
 * @return Name of type.
 */
int
secinfo_type_is_scap (const char* type)
{
  return (strcasecmp (type, "cpe") == 0)
         || (strcasecmp (type, "cve") == 0);
}
