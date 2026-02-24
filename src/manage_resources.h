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

#include "manage_resources_types.h"
#include "iterator.h"
#include "manage_get.h"


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
resource_count (const char *, const get_data_t *);

int
manage_resource_name (const char *, const char *, char **);

int
manage_trash_resource_name (const char *, const char *, char **);

int
resource_id_deprecated (const char *, const char *);

void
set_resource_id_deprecated (const char *, const char *, gboolean);

#endif /* not _GVMD_MANAGE_RESOURCES_H */
