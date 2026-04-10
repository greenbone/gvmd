/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_notes.h"
#include "manage_sql_resources.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Find a note for a specific permission, given a UUID.
 *
 * @param[in]   uuid        UUID of note.
 * @param[out]  note        Note return, 0 if successfully failed to find note.
 * @param[in]   permission  Permission.
 *
 * @return FALSE on success (including if failed to find note), TRUE on error.
 */
gboolean
find_note_with_permission (const char* uuid, note_t* note,
                           const char *permission)
{
  return find_resource_with_permission ("note", uuid, note, permission, 0);
}
