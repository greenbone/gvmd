/* Copyright (C) 2009-2022 Greenbone AG
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
 * @file
 * @brief GVM: Utilities for LSC credential package generation
 *
 * This file provides support for generating packages for LSC credentials.
 */

#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <gvm/util/fileutils.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"


/* Key creation. */

/**
 * @brief Create an ssh key for local security checks.
 *
 * Forks and creates a key for local checks by calling
 * 'ssh-keygen -t rsa -f filepath -C "comment" -P "passhprase"'.
 * A directory will be created if it does not exist.
 *
 * @param[in]  comment     Comment to use.
 * @param[in]  passphrase  Passphrase for key, must be longer than 4 characters.
 * @param[in]  privpath    Filename of the key file.
 *
 * @return 0 if successful, -1 otherwise.
 */
static int
create_ssh_key (const char *comment, const char *passphrase,
                const char *privpath)
{
  gchar *astdout = NULL;
  gchar *astderr = NULL;
  GError *err = NULL;
  gint exit_status = 0;
  gchar *dir;
  char *command;

  /* Sanity-check essential parameters. */

  if (!comment || comment[0] == '\0')
    {
      g_warning ("%s: comment must be set", __func__);
      return -1;
    }
  if (!passphrase || strlen (passphrase) < 5)
    {
      g_warning ("%s: password must be longer than 4 characters", __func__);
      return -1;
    }

  /* Sanity check files. */

  dir = g_path_get_dirname (privpath);
  if (g_mkdir_with_parents (dir, 0755 /* "rwxr-xr-x" */ ))
    {
      g_warning ("%s: failed to access %s", __func__, dir);
      g_free (dir);
      return -1;
    }
  g_free (dir);

  /* Spawn ssh-keygen. */
  command = g_strconcat ("ssh-keygen -t rsa -f ", privpath, " -C \"", comment,
                         "\" -P \"", passphrase, "\"", NULL);
  g_debug ("command: ssh-keygen -t rsa -f %s -C \"%s\" -P \"********\"",
           privpath, comment);

  if ((g_spawn_command_line_sync (command, &astdout, &astderr, &exit_status,
                                  &err)
       == FALSE)
      || (WIFEXITED (exit_status) == 0)
      || WEXITSTATUS (exit_status))
    {
      if (err)
        {
          g_warning ("%s: failed to create private key: %s",
                     __func__, err->message);
          g_error_free (err);
        }
      else
        g_warning ("%s: failed to create private key", __func__);
      g_debug ("%s: key-gen failed with %d (WIF %i, WEX %i).\n",
               __func__, exit_status, WIFEXITED (exit_status),
               WEXITSTATUS (exit_status));
      g_debug ("%s: stdout: %s", __func__, astdout);
      g_debug ("%s: stderr: %s", __func__, astderr);
      g_free (command);
      g_free (astdout);
      g_free (astderr);
      return -1;
    }
  g_free (command);
  g_free (astdout);
  g_free (astderr);
  return 0;
}

/**
 * @brief Create local security check (LSC) keys.
 *
 * @param[in]   password     Password.
 * @param[out]  private_key  Private key.
 *
 * @return 0 success, -1 error.
 */
int
lsc_user_keys_create (const gchar *password,
                      gchar **private_key)
{
  GError *error;
  gsize length;
  char key_dir[] = "/tmp/openvas_key_XXXXXX";
  gchar *key_path = NULL;
  int ret = -1;

  /* Make a directory for the keys. */

  if (mkdtemp (key_dir) == NULL)
    return -1;

  /* Create private key. */
  key_path = g_build_filename (key_dir, "key", NULL);
  if (create_ssh_key ("Key generated by GVM", password, key_path))
    goto free_exit;

  error = NULL;
  g_file_get_contents (key_path, private_key, &length, &error);
  if (error)
    {
      g_error_free (error);
      goto free_exit;
    }
  ret = 0;
 free_exit:

  g_free (key_path);
  gvm_file_remove_recurse (key_dir);
  return ret;
}


/* RPM package generation. */

/**
 * @brief Attempts creation of RPM packages to create a user and install a
 * @brief public key file for it.
 *
 * @param[in]  username         Name of user.
 * @param[in]  public_key_path  Location of public key.
 * @param[in]  to_filename      Destination filename for RPM.
 *
 * @return Path to rpm file if successful, NULL otherwise.
 */
static gboolean
lsc_user_rpm_create (const gchar *username,
                     const gchar *public_key_path,
                     const gchar *to_filename)
{
  gint exit_status;
  gchar *new_pubkey_filename = NULL;
  gchar *pubkey_basename = NULL;
  gchar **cmd;
  char tmpdir[] = "/tmp/lsc_user_rpm_create_XXXXXX";
  gboolean success = TRUE;
  gchar *standard_out = NULL;
  gchar *standard_err = NULL;

  /* Create a temporary directory. */

  g_debug ("%s: create temporary directory", __func__);
  if (mkdtemp (tmpdir) == NULL)
    return FALSE;
  g_debug ("%s: temporary directory: %s", __func__, tmpdir);

  /* Copy the public key into the temporary directory. */

  g_debug ("%s: copy key to temporary directory", __func__);
  pubkey_basename = g_strdup_printf ("%s.pub", username);
  new_pubkey_filename = g_build_filename (tmpdir, pubkey_basename, NULL);
  if (gvm_file_copy (public_key_path, new_pubkey_filename)
      == FALSE)
    {
      g_warning ("%s: failed to copy key file %s to %s",
                 __func__, public_key_path, new_pubkey_filename);
      g_free (pubkey_basename);
      g_free (new_pubkey_filename);
      return FALSE;
    }

  /* Execute create-rpm script with the temporary directory as the
   * target and the public key in the temporary directory as the key. */

  g_debug ("%s: Attempting RPM build", __func__);
  cmd = (gchar **) g_malloc (6 * sizeof (gchar *));
  cmd[0] = g_build_filename (GVM_DATA_DIR,
                             "gvm-lsc-rpm-creator",
                             NULL);
  cmd[1] = g_strdup (username);
  cmd[2] = g_strdup (new_pubkey_filename);
  cmd[3] = g_strdup (tmpdir);
  cmd[4] = g_strdup (to_filename);
  cmd[5] = NULL;
  g_debug ("%s: Spawning in %s: %s %s %s %s %s",
           __func__, tmpdir, cmd[0], cmd[1], cmd[2], cmd[3], cmd[4]);
  if ((g_spawn_sync (tmpdir,
                     cmd,
                     NULL,                  /* Environment. */
                     G_SPAWN_SEARCH_PATH,
                     NULL,                  /* Setup function. */
                     NULL,
                     &standard_out,
                     &standard_err,
                     &exit_status,
                     NULL)
       == FALSE)
      || (WIFEXITED (exit_status) == 0)
      || WEXITSTATUS (exit_status))
    {
      g_warning ("%s: failed to create the rpm: %d (WIF %i, WEX %i)",
                 __func__,
                 exit_status,
                 WIFEXITED (exit_status),
                 WEXITSTATUS (exit_status));
      g_debug ("%s: stdout: %s", __func__, standard_out);
      g_debug ("%s: stderr: %s", __func__, standard_err);
      success = FALSE;
    }

  g_free (cmd[0]);
  g_free (cmd[1]);
  g_free (cmd[2]);
  g_free (cmd[3]);
  g_free (cmd[4]);
  g_free (cmd);
  g_free (pubkey_basename);
  g_free (new_pubkey_filename);
  g_free (standard_out);
  g_free (standard_err);

  /* Remove the copy of the public key and the temporary directory. */

  if (gvm_file_remove_recurse (tmpdir) != 0 && success == TRUE)
    {
      g_warning ("%s: failed to remove temporary directory %s",
                 __func__, tmpdir);
      success = FALSE;
    }

  return success;
}

/**
 * @brief Recreate RPM package.
 *
 * @param[in]   name         User name.
 * @param[in]   public_key   Public key.
 * @param[out]  rpm          RPM package.
 * @param[out]  rpm_size     Size of RPM package, in bytes.
 *
 * @return 0 success, -1 error.
 */
int
lsc_user_rpm_recreate (const gchar *name, const char *public_key,
                       void **rpm, gsize *rpm_size)
{
  GError *error;
  char rpm_dir[] = "/tmp/rpm_XXXXXX";
  char key_dir[] = "/tmp/key_XXXXXX";
  gchar *rpm_path, *public_key_path;
  int ret = -1;

  /* Make a directory for the key. */

  if (mkdtemp (key_dir) == NULL)
    return -1;

  /* Write public key to file. */

  error = NULL;
  public_key_path = g_build_filename (key_dir, "key.pub", NULL);
  g_file_set_contents (public_key_path, public_key, strlen (public_key),
                       &error);
  if (error)
    goto free_exit;

  /* Create RPM package. */

  if (mkdtemp (rpm_dir) == NULL)
    goto free_exit;
  rpm_path = g_build_filename (rpm_dir, "p.rpm", NULL);
  g_debug ("%s: rpm_path: %s", __func__, rpm_path);
  if (lsc_user_rpm_create (name, public_key_path, rpm_path) == FALSE)
    {
      g_free (rpm_path);
      goto rm_exit;
    }

  /* Read the package into memory. */

  error = NULL;
  g_file_get_contents (rpm_path, (gchar **) rpm, rpm_size, &error);
  g_free (rpm_path);
  if (error)
    {
      g_error_free (error);
      goto rm_exit;
    }

  /* Return. */

  ret = 0;

 rm_exit:

  gvm_file_remove_recurse (rpm_dir);

 free_exit:

  g_free (public_key_path);

  gvm_file_remove_recurse (key_dir);

  return ret;
}


/* Deb generation. */

/**
 * @brief Attempts creation of Debian packages to create a user and install a
 * @brief public key file for it.
 *
 * @param[in]  username         Name of user.
 * @param[in]  public_key_path  Location of public key.
 * @param[in]  to_filename      Destination filename for RPM.
 * @param[in]  maintainer       Maintainer email address.
 *
 * @return Path to rpm file if successful, NULL otherwise.
 */
static gboolean
lsc_user_deb_create (const gchar *username,
                     const gchar *public_key_path,
                     const gchar *to_filename,
                     const gchar *maintainer)
{
  gint exit_status;
  gchar *new_pubkey_filename = NULL;
  gchar *pubkey_basename = NULL;
  gchar **cmd;
  char tmpdir[] = "/tmp/lsc_user_deb_create_XXXXXX";
  gboolean success = TRUE;
  gchar *standard_out = NULL;
  gchar *standard_err = NULL;

  /* Create a temporary directory. */

  g_debug ("%s: create temporary directory", __func__);
  if (mkdtemp (tmpdir) == NULL)
    return FALSE;
  g_debug ("%s: temporary directory: %s", __func__, tmpdir);

  /* Copy the public key into the temporary directory. */

  g_debug ("%s: copy key to temporary directory", __func__);
  pubkey_basename = g_strdup_printf ("%s.pub", username);
  new_pubkey_filename = g_build_filename (tmpdir, pubkey_basename, NULL);
  if (gvm_file_copy (public_key_path, new_pubkey_filename)
      == FALSE)
    {
      g_warning ("%s: failed to copy key file %s to %s",
                 __func__, public_key_path, new_pubkey_filename);
      g_free (pubkey_basename);
      g_free (new_pubkey_filename);
      return FALSE;
    }

  /* Execute create-deb script with the temporary directory as the
   * target and the public key in the temporary directory as the key. */

  g_debug ("%s: Attempting DEB build", __func__);
  cmd = (gchar **) g_malloc (7 * sizeof (gchar *));
  cmd[0] = g_build_filename (GVM_DATA_DIR,
                             "gvm-lsc-deb-creator",
                             NULL);
  cmd[1] = g_strdup (username);
  cmd[2] = g_strdup (new_pubkey_filename);
  cmd[3] = g_strdup (tmpdir);
  cmd[4] = g_strdup (to_filename);
  cmd[5] = g_strdup (maintainer);
  cmd[6] = NULL;
  g_debug ("%s: Spawning in %s: %s %s %s %s %s %s",
           __func__, tmpdir,
           cmd[0], cmd[1], cmd[2], cmd[3], cmd[4], cmd[5]);
  if ((g_spawn_sync (tmpdir,
                     cmd,
                     NULL,                  /* Environment. */
                     G_SPAWN_SEARCH_PATH,
                     NULL,                  /* Setup function. */
                     NULL,
                     &standard_out,
                     &standard_err,
                     &exit_status,
                     NULL)
       == FALSE)
      || (WIFEXITED (exit_status) == 0)
      || WEXITSTATUS (exit_status))
    {
      g_warning ("%s: failed to create the deb: %d (WIF %i, WEX %i)",
                 __func__,
                 exit_status,
                 WIFEXITED (exit_status),
                 WEXITSTATUS (exit_status));
      g_debug ("%s: stdout: %s", __func__, standard_out);
      g_debug ("%s: stderr: %s", __func__, standard_err);
      success = FALSE;
    }

  g_free (cmd[0]);
  g_free (cmd[1]);
  g_free (cmd[2]);
  g_free (cmd[3]);
  g_free (cmd[4]);
  g_free (cmd[5]);
  g_free (cmd);
  g_free (pubkey_basename);
  g_free (new_pubkey_filename);
  g_free (standard_out);
  g_free (standard_err);

  /* Remove the copy of the public key and the temporary directory. */

  if (gvm_file_remove_recurse (tmpdir) != 0 && success == TRUE)
    {
      g_warning ("%s: failed to remove temporary directory %s",
                 __func__, tmpdir);
      success = FALSE;
    }

  return success;
}

/**
 * @brief Recreate DEB package.
 *
 * @param[in]   name         User name.
 * @param[in]   public_key   Public key.
 * @param[in]   maintainer   The maintainer email address.
 * @param[out]  deb          DEB package.
 * @param[out]  deb_size     Size of DEB package, in bytes.
 *
 * @return 0 success, -1 error.
 */
int
lsc_user_deb_recreate (const gchar *name, const char *public_key,
                       const char *maintainer,
                       void **deb, gsize *deb_size)
{
  GError *error;
  char deb_dir[] = "/tmp/deb_XXXXXX";
  char key_dir[] = "/tmp/key_XXXXXX";
  gchar *deb_path, *public_key_path;
  int ret = -1;

  /* Make a directory for the key. */

  if (mkdtemp (key_dir) == NULL)
    return -1;

  /* Write public key to file. */

  error = NULL;
  public_key_path = g_build_filename (key_dir, "key.pub", NULL);
  g_file_set_contents (public_key_path, public_key, strlen (public_key),
                       &error);
  if (error)
    goto free_exit;

  /* Create DEB package. */

  if (mkdtemp (deb_dir) == NULL)
    goto free_exit;
  deb_path = g_build_filename (deb_dir, "p.deb", NULL);
  g_debug ("%s: deb_path: %s", __func__, deb_path);
  if (lsc_user_deb_create (name, public_key_path, deb_path, maintainer)
        == FALSE)
    {
      g_free (deb_path);
      goto rm_exit;
    }

  /* Read the package into memory. */

  error = NULL;
  g_file_get_contents (deb_path, (gchar **) deb, deb_size, &error);
  g_free (deb_path);
  if (error)
    {
      g_error_free (error);
      goto rm_exit;
    }

  /* Return. */

  ret = 0;

 rm_exit:

  gvm_file_remove_recurse (deb_dir);

 free_exit:

  g_free (public_key_path);

  gvm_file_remove_recurse (key_dir);

  return ret;
}


/* Exe generation. */

/**
 * @brief Create a Windows EXE installer for adding a user.
 *
 * @param[in]  username     Name of user.
 * @param[in]  password     Password of user.
 * @param[in]  to_filename  Destination filename for package.
 *
 * @return 0 success, -1 error.
 */
static gboolean
lsc_user_exe_create (const gchar *username,
                     const gchar *password,
                     const gchar *to_filename)
{
  gint exit_status;
  gchar **cmd;
  char tmpdir[] = "/tmp/lsc_user_exe_create_XXXXXX";
  gchar *password_file_path, *template_file_path;
  gboolean ret = 0;
  gchar *standard_out = NULL;
  gchar *standard_err = NULL;
  GError *error = NULL;

  /* Create a temporary directory. */

  g_debug ("%s: create temporary directory", __func__);
  if (mkdtemp (tmpdir) == NULL)
    return FALSE;
  g_debug ("%s: temporary directory: %s", __func__, tmpdir);

  /* Create password file. */

  g_debug ("%s: create password file", __func__);
  password_file_path = g_build_filename (tmpdir, "pw.txt", NULL);
  if (g_file_set_contents (password_file_path, password, -1, &error) == FALSE)
    {
      g_warning ("%s: failed to create password file %s: %s",
                 __func__, password_file_path, error->message);
      g_free (password_file_path);
      return -1;
    }

  /* Build template file path */
  template_file_path = g_build_filename (GVMD_DATA_DIR, "template.nsis", NULL);

  /* Execute create-deb script with the temporary directory as the
   * target and the public key in the temporary directory as the key. */

  g_debug ("%s: Attempting EXE build", __func__);
  cmd = (gchar **) g_malloc (7 * sizeof (gchar *));
  cmd[0] = g_build_filename (GVM_DATA_DIR,
                             "gvm-lsc-exe-creator",
                             NULL);
  cmd[1] = g_strdup (username);
  cmd[2] = g_strdup (password_file_path);
  cmd[3] = g_strdup (tmpdir);
  cmd[4] = g_strdup (to_filename);
  cmd[5] = g_strdup (template_file_path);
  cmd[6] = NULL;
  g_debug ("%s: Spawning in %s: %s %s %s %s %s %s",
           __func__, tmpdir,
           cmd[0], cmd[1], cmd[2], cmd[3], cmd[4], cmd[5]);
  if ((g_spawn_sync (tmpdir,
                     cmd,
                     NULL,                 /* Environment. */
                     G_SPAWN_SEARCH_PATH,
                     NULL,                 /* Setup function. */
                     NULL,
                     &standard_out,
                     &standard_err,
                     &exit_status,
                     NULL)
       == FALSE)
      || (WIFEXITED (exit_status) == 0)
      || WEXITSTATUS (exit_status))
    {
      g_warning ("%s: failed to create the exe: %d (WIF %i, WEX %i)",
                 __func__,
                 exit_status,
                 WIFEXITED (exit_status),
                 WEXITSTATUS (exit_status));
      g_message ("%s: stdout: %s", __func__, standard_out);
      g_message ("%s: stderr: %s", __func__, standard_err);
      ret = -1;
    }

  g_free (cmd[0]);
  g_free (cmd[1]);
  g_free (cmd[2]);
  g_free (cmd[3]);
  g_free (cmd[4]);
  g_free (cmd[5]);
  g_free (cmd);
  g_free (password_file_path);
  g_free (template_file_path);
  g_free (standard_out);
  g_free (standard_err);

  /* Remove the copy of the public key and the temporary directory. */

  if (gvm_file_remove_recurse (tmpdir) != 0 && ret == 0)
    {
      g_warning ("%s: failed to remove temporary directory %s",
                 __func__, tmpdir);
      ret = -1;
    }

  return ret;
}

/**
 * @brief Recreate NSIS package.
 *
 * @param[in]   name         User name.
 * @param[in]   password     Password.
 * @param[out]  exe          NSIS package.
 * @param[out]  exe_size     Size of NSIS package, in bytes.
 *
 * @return 0 success, -1 error.
 */
int
lsc_user_exe_recreate (const gchar *name, const gchar *password,
                       void **exe, gsize *exe_size)
{
  GError *error;
  char exe_dir[] = "/tmp/exe_XXXXXX";
  gchar *exe_path;
  int ret = -1;

  /* Create NSIS package. */

  if (mkdtemp (exe_dir) == NULL)
    return -1;
  exe_path = g_build_filename (exe_dir, "p.nsis", NULL);
  if (lsc_user_exe_create (name, password, exe_path))
    goto rm_exit;

  /* Read the package into memory. */

  error = NULL;
  g_file_get_contents (exe_path, (gchar **) exe, exe_size, &error);
  if (error)
    {
      g_error_free (error);
      goto rm_exit;
    }

  /* Return. */

  ret = 0;

 rm_exit:

  gvm_file_remove_recurse (exe_dir);

  g_free (exe_path);

  return ret;
}
