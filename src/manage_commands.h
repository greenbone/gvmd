/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Generic command handling headers.
 *
 * Non-SQL generic command handling headers for the GVM management layer.
 */

#ifndef GVMD_MANAGE_COMMANDS_H
#define GVMD_MANAGE_COMMANDS_H

#include <glib.h>

/**
 * @brief A command.
 */
typedef struct
{
  gchar *name;     ///< Command name.
  gchar *summary;  ///< Summary of command.
} command_t;

/**
 * @brief The GMP command list.
 */
extern command_t gmp_commands[];

int
valid_gmp_command (const char*);

gchar *
gmp_command_type (const char*);

int
gmp_command_takes_resource (const char*);


#endif /* GVMD_MANAGE_COMMANDS_H */
