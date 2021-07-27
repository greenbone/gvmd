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
  int  schema_version;    ///< Version of the license file schema
  char *title;            ///< Short title summarizing the license
  char *license_type;     ///< Type of license, e.g. Trial or Full license
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
  char *model;        ///< Appliance model, e.g. "GSM ONE"
  char *model_type;   ///< Appliance model type, e.g. "Sensor"
  int cpu_cores;      ///< Number of CPU cores
  int memory;         ///< Amount of RAM in MiB
} license_hardware_t;

license_hardware_t *
license_hardware_new ();

void
license_hardware_free (license_hardware_t *);

/**
 * @brief Defines the information contained in a license
 */
typedef struct {
  license_meta_t *meta;         ///< License metadata
  license_hardware_t *hardware; ///< Hardware and appliance information
  GTree *features;              ///< Map of enabled or disabled features
  GTree *limits;                ///< Numeric limits, e.g. max. hosts per target
  GTree *keys;                  ///< Base64 encoded access keys, e.g. feed key
  GTree *signature;             ///< Signature info of the license
} license_data_t;

license_data_t *
license_data_new ();

void
license_data_free (license_data_t *);


/* Actions */

int
manage_update_license_file (const char *);

int
manage_get_license (char **, license_data_t **, char **);
