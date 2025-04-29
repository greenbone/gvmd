/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file manage_agent_installers.h
 * @brief GVM manage layer headers: Agent installers.
 *
 * General management headers of agent installers.
 */

#ifndef _GVMD_MANAGE_AGENT_INSTALLERS_H
#define _GVMD_MANAGE_AGENT_INSTALLERS_H

#include "manage.h"
#include "iterator.h"
#include "gmp_get.h"

typedef resource_t agent_installer_t;

typedef struct {
  agent_installer_t row_id;
  gchar *uuid;
  gchar *name;
  gchar *description;
  gchar *content_type;
  gchar *file_extension;
  gchar *installer_path;
  gchar *version;
  gchar *checksum;
  GPtrArray *cpes;
  int file_size;
  time_t creation_time;
  time_t modification_time;
} agent_installer_data_t;

void
agent_installer_data_free (agent_installer_data_t *);

typedef struct {
  gchar *criteria;
  gchar *version_start_incl;
  gchar *version_start_excl;
  gchar *version_end_incl;
  gchar *version_end_excl;
} agent_installer_cpe_data_t;

void
agent_installer_cpe_data_free (agent_installer_cpe_data_t *);

gboolean
agent_installer_file_is_valid (const char *, const char *, int, gchar**);


time_t
get_meta_agent_installers_last_update ();

void
update_meta_agent_installers_last_update ();

const gchar *
feed_dir_agent_installers ();

gboolean
agent_installers_feed_metadata_file_exists ();

gboolean
should_sync_agent_installers ();

void
manage_sync_agent_installers ();

int
create_agent_installer_from_data (agent_installer_data_t *agent_installer_data);

int
update_agent_installer_from_data (agent_installer_t,
                                  gboolean,
                                  agent_installer_data_t *agent_installer_data);

int
agent_installer_count (const get_data_t *get);

agent_installer_t
agent_installer_by_uuid (const char *, int);

time_t
agent_installer_modification_time (agent_installer_t, int);

int
init_agent_installer_iterator (iterator_t*, get_data_t*);

const char *
agent_installer_iterator_description (iterator_t*);

const char *
agent_installer_iterator_content_type (iterator_t*);

const char *
agent_installer_iterator_file_extension (iterator_t*);

const char *
agent_installer_iterator_installer_path (iterator_t*);

const char *
agent_installer_iterator_version (iterator_t*);

const char *
agent_installer_iterator_checksum (iterator_t*);

int
agent_installer_iterator_file_size (iterator_t*);

int
agent_installer_in_use (agent_installer_t);

int
trash_agent_installer_in_use(agent_installer_t);

int
agent_installer_writable (agent_installer_t);

int
trash_agent_installer_writable(agent_installer_t);


#endif /* not _GVMD_MANAGE_AGENT_INSTALLERS_H */
