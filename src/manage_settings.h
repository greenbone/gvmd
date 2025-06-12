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

/**
 * @brief UUID of setting.
 */
#define SETTING_UUID_AUTO_CACHE_REBUILD "a09285b0-2d47-49b6-a4ef-946ee71f1d5c"

/**
 * @brief UUID of setting.
 */
#define SETTING_UUID_AUTO_REFRESH "578a1c14-e2dc-45ef-a591-89d31391d007"

/**
 * @brief UUID of 'CVE-CPE Matching Version' setting.
 */
#define SETTING_UUID_CVE_CPE_MATCHING_VERSION "2e8a8ccc-219f-4a82-824a-3ad88b6d4029"

/**
 * @brief UUID of setting.
 */
#define SETTING_UUID_DEFAULT_SEVERITY "7eda49c5-096c-4bef-b1ab-d080d87300df"

/**
 * @brief UUID of 'Default CA Cert' setting.
 */
#define SETTING_UUID_DEFAULT_CA_CERT "9ac801ea-39f8-11e6-bbaa-28d24461215b"

/**
 * @brief UUID of setting.
 */
#define SETTING_UUID_DYNAMIC_SEVERITY "77ec2444-e7f2-4a80-a59b-f4237782d93f"

/**
 * @brief UUID of 'Note/Override Excerpt Size' setting.
 */
#define SETTING_UUID_EXCERPT_SIZE "9246a0f6-c6ad-44bc-86c2-557a527c8fb3"

/**
 * @brief UUID of 'Feed Import Owner' setting.
 */
#define SETTING_UUID_FEED_IMPORT_OWNER "78eceaec-3385-11ea-b237-28d24461215b"

/**
 * @brief UUID of 'Agent Owner' setting.
 */
#define SETTING_UUID_AGENT_OWNER "1ee1f106-8b2e-461c-b426-7f5d76001b29"

/**
 * @brief UUID of 'Feed Import Roles' setting.
 */
#define SETTING_UUID_FEED_IMPORT_ROLES "ff000362-338f-11ea-9051-28d24461215b"

/**
 * @brief UUID of setting.
 */
#define SETTING_UUID_FILE_DETAILS "a6ac88c5-729c-41ba-ac0a-deea4a3441f2"

/**
 * @brief UUID of setting.
 */
#define SETTING_UUID_FILE_LIST "0872a6ed-4f85-48c5-ac3f-a5ef5e006745"

/**
 * @brief UUID of setting.
 */
#define SETTING_UUID_FILE_REPORT "e1a2ae0b-736e-4484-b029-330c9e15b900"

/**
 * @brief UUID of 'Debian LSC Package Maintainer' setting.
 */
#define SETTING_UUID_LSC_DEB_MAINTAINER "2fcbeac8-4237-438f-b52a-540a23e7af97"

/**
 * @brief UUID of 'Max Rows Per Page' setting.
 */
#define SETTING_UUID_MAX_ROWS_PER_PAGE "76374a7a-0569-11e6-b6da-28d24461215b"

/**
 * @brief UUID of setting.
 */
#define SETTING_UUID_PREFERRED_LANG "6765549a-934e-11e3-b358-406186ea4fc5"

/**
 * @brief UUID of 'Rows Per Page' setting.
 */
#define SETTING_UUID_ROWS_PER_PAGE "5f5a8712-8017-11e1-8556-406186ea4fc5"

/**
 * @brief UUID of 'SecInfo SQL Buffer Threshold' setting.
 */
#define SETTING_UUID_SECINFO_SQL_BUFFER_THRESHOLD "316275a9-3629-49ad-9cea-5b3ab155b93f"

/**
 * @brief UUID of 'User Interface Date Format' setting.
 */
#define SETTING_UUID_USER_INTERFACE_DATE_FORMAT "d9857b7c-1159-4193-9bc0-18fae5473a69"

/**
 * @brief UUID of 'User Interface Time Format' setting.
 */
#define SETTING_UUID_USER_INTERFACE_TIME_FORMAT "11deb7ff-550b-4950-aacf-06faeb7c61b9"

/**
 * @brief Type for a function getting a setting value as a string.
 */
typedef int (*setting_value_func)(const char*, char **);

/**
 * @brief Type for a function getting a setting value as an integer.
 */
typedef int (*setting_value_int_func)(const char*, int *);


int
setting_value (const char *, char **);

int
setting_value_int (const char *, int *);

void
init_manage_settings_funcs (setting_value_func,
                            setting_value_int_func);


#endif /* GVMD_MANAGE_SETTINGS_H */
