/* Copyright (C) 2020-2021 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file manage_license.c
 * @brief GVM management layer: License information headers.
 *
 * Headers for non-SQL license information code for the GVM management layer.
 */

#include <glib.h>

/* Data types */

/**
 * @brief Defines the metadata of a license
 */
typedef struct {
  char *id;               ///< Unique Identifier of the license
  char *version;          ///< Version of the license file schema
  char *title;            ///< Short title summarizing the license
  char *type;             ///< Type of license, e.g. trial or commercial
  char *customer_name;    ///< Name of the customer
  time_t created;         ///< Time the license was created
  time_t begins;          ///< Time after which the license becomes valid
  time_t expires;         ///< Time the license expires
} license_meta_t;

license_meta_t *
license_meta_new ();

void
license_meta_free (license_meta_t *);

/**
 * @brief Defines the hardware and appliance information of a license
 */
typedef struct {
  char *model;        ///< Appliance model, e.g. "one", "ceno", "450", ...
  char *model_type;   ///< Appliance model type, e.g. "virtual" or "hardware"
  gboolean sensor;    ///< Whether the license is applied to a sensor or not
} license_appliance_t;

license_appliance_t *
license_appliance_new ();

void
license_appliance_free (license_appliance_t *);

/**
 * @brief Defines the information contained in a license
 */
typedef struct {
  license_meta_t *meta;           ///< License metadata
  license_appliance_t *appliance; ///< Hardware and appliance information
  GTree *keys;         ///< Base64 encoded access keys, e.g. feed key
  GTree *signatures;   ///< Signature info of the license
} license_data_t;

license_data_t *
license_data_new ();

void
license_data_free (license_data_t *);


/* Actions */

int
manage_update_license_file (const char *);

int
manage_get_license (char **, license_data_t **);
