/* Copyright (C) 2020-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/*
 * @file
 * @brief Headers for Greenbone Vulnerability Manager: Manage lib: Preferences.
 */

#ifndef _GVMD_MANAGE_PREFERENCES_H
#define _GVMD_MANAGE_PREFERENCES_H

#include <gvm/base/array.h>

/**
 * @brief An NVT preference.
 */
typedef struct
{
  char *name;          ///< Full name of preference, including OID etc.
  char *pref_name;     ///< Name of preference.
  char *id;            ///< ID of preference.
  char *type;          ///< Type of preference (radio, password, ...).
  char *value;         ///< Value of preference.
  char *nvt_name;      ///< Name of NVT preference affects.
  char *nvt_oid;       ///< OID of NVT preference affects.
  array_t *alts;       ///< Array of gchar's.  Alternate values for radio type.
  char *default_value; ///< Default value of preference.
  char *hr_name;       ///< Extended, more human-readable name.
  int free_strings;    ///< Whether string fields are freed by preference_free.
} preference_t;

gpointer
preference_new (char *, char *, char *, char *, char *,
                char *, array_t *, char*, char *, int);

void
preference_free (preference_t *);

void
cleanup_import_preferences (array_t *);

#endif /* not _GVMD_MANAGE_PREFERENCES_H */
