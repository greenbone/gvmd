/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Generic resource type handling headers.
 *
 * Non-SQL generic resource type handling headers for the GVM management layer.
 */

#ifndef _GVMD_MANAGE_RESOURCES_H
#define _GVMD_MANAGE_RESOURCES_H

#include "iterator.h"


/* Resource types */
#if ENABLE_AGENTS
typedef resource_t agent_t;
typedef resource_t agent_group_t;
typedef resource_t agent_installer_t;
#endif
typedef resource_t alert_t;
typedef resource_t asset_snapshot_t;
typedef resource_t config_t;
typedef resource_t credential_store_t;
typedef resource_t credential_t;
typedef resource_t filter_t;
typedef resource_t group_t;
typedef resource_t host_t;
typedef resource_t note_t;
typedef resource_t nvt_t;
typedef resource_t oci_image_target_t;
typedef resource_t override_t;
typedef resource_t permission_t;
typedef resource_t port_list_t;
typedef resource_t port_range_t;
typedef resource_t report_config_param_t;
typedef resource_t report_config_t;
typedef resource_t report_format_param_t;
typedef resource_t report_format_t;
typedef resource_t report_host_t;
typedef resource_t report_t;
typedef resource_t result_t;
typedef resource_t role_t;
typedef resource_t scanner_t;
typedef resource_t schedule_t;
typedef resource_t setting_t;
typedef resource_t tag_t;
typedef resource_t target_t;
typedef resource_t task_t;
typedef resource_t ticket_t;
typedef resource_t tls_certificate_t;
typedef resource_t user_t;


/* Resource type information. */

int
valid_type (const char*);

int
valid_subtype (const char*);

const char *
type_db_name (const char*);

int
type_is_asset_subtype (const char *);

int
type_is_info_subtype (const char *);

int
type_is_report_subtype (const char *);

int
type_is_task_subtype (const char *);

int
type_is_config_subtype (const char *);

int
type_named (const char *);

int
type_globally_unique (const char *);

int
type_has_comment (const char *);

int
type_has_trash (const char *);

int
type_owned (const char *);

int
type_trash_in_table (const char *);


/* SecInfo specific resource type information. */

const char *
secinfo_type_name_plural (const char*);

const char *
secinfo_type_name (const char*);

int
secinfo_type_is_scap (const char*);


/* Everything else. */

int
manage_resource_name (const char *, const char *, char **);

int
manage_trash_resource_name (const char *, const char *, char **);

int
resource_id_deprecated (const char *, const char *);

void
set_resource_id_deprecated (const char *, const char *, gboolean);

#endif /* not _GVMD_MANAGE_RESOURCES_H */
