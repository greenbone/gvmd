/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file manage_settings.h
 * @brief GVM management layer: User Settings headers.
 *
 * User settings headers for the GVM management layer.
 */

#ifndef GVMD_MANAGE_SETTINGS_H
#define GVMD_MANAGE_SETTINGS_H

typedef int (*setting_value_func)(const char*, char **);

typedef int (*setting_value_int_func)(const char*, int *);

int
setting_value (const char *, char **);

int
setting_value_int (const char *, int *);

void
init_manage_settings_funcs (setting_value_func,
                            setting_value_int_func);


#endif /* GVMD_MANAGE_SETTINGS_H */
