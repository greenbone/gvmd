/* OpenVAS Manager
 * $Id$
 * Description: LSC user credentials package generation.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@intevation.de>
 * Michael Wiegand   <michael.wiegand@intevation.de>
 * Felix Wolfsteller <felix.wolfsteller@intevation.de>
 *
 * Copyright:
 * Copyright (C) 2009 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <glib/gstdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <openvas/openvas_ssh_login.h>
#include <openvas/system.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"


// FIX Munge helpers.

#define show_error g_debug
#define _(string) string

/** @todo Copied check_is_file and check_is_dir from administrator. */

/**
 * @brief Checks whether a file is a directory or not.
 *
 * This is a replacement for the g_file_test functionality which is reported
 * to be unreliable under certain circumstances, for example if this
 * application and glib are compiled with a different libc.
 *
 * @todo FIXME: handle symbolic links
 * @todo Move to libs?
 *
 * @return 1 if parameter is directory, 0 if it is not, -1 if it does not
 * exist or could not be accessed.
 */
static int
check_is_file (const char* name)
{
  struct stat sb;

  if (stat (name, &sb))
    {
      return -1;
    }
  else
    {
      return (S_ISREG (sb.st_mode));
    }
}

/**
 * @brief Checks whether a file is a directory or not.
 *
 * This is a replacement for the g_file_test functionality which is reported
 * to be unreliable under certain circumstances, for example if this
 * application and glib are compiled with a different libc.
 *
 * @todo FIXME: handle symbolic links
 * @todo Move to libs?
 *
 * @return 1 if parameter is directory, 0 if it is not, -1 if it does not
 * exist or could not be accessed.
 */
static int
check_is_dir (const char* name)
{
  struct stat sb;

  if (stat (name, &sb))
    {
      return -1;
    }
  else
    {
      return (S_ISDIR (sb.st_mode));
    }
}


/** @todo Copied verbatim from openvas-client/src/util/file_utils.c. */

/**
 * @brief Recursively removes files and directories.
 *
 * This function will recursively call itself to delete a path and any
 * contents of this path.
 *
 * @param pathname The name of the file to be deleted from the filesystem.
 *
 * @return 0 if the name was successfully deleted, -1 if an error occurred.
 * Please note that errno is currently not guaranteed to contain the correct
 * value if -1 is returned.
 */
static int
file_utils_rmdir_rf (const gchar * pathname)
{
  if (check_is_dir (pathname) == 1)
    {
      GError *error = NULL;
      GDir *directory = g_dir_open (pathname, 0, &error);

      if (directory == NULL)
        {
          g_warning ("g_dir_open(%s) failed - %s\n", pathname, error->message);
          g_error_free (error);
          // errno should be set when we return -1 to maintain remove()
          // compatibility.
          return -1;
        }
      else
        {
          int ret = 0;
          const gchar *entry = NULL;

          while ((entry = g_dir_read_name (directory)) && (ret == 0))
            {
              ret = file_utils_rmdir_rf (g_build_filename (pathname, entry, NULL));
              if (ret != 0)
                {
                  g_warning ("Failed to remove %s from %s!", entry, pathname);
                  g_dir_close (directory);
                  return ret;
                }
            }
          g_dir_close (directory);
        }
    }

  return g_remove (pathname);
}

/**
 * @brief Reads contents from a source file into a destination file.
 *
 * The source file is read into memory, so it is inefficient and likely to fail
 * for really big files.
 * If the destination file does exist already, it will be overwritten.
 *
 * @returns TRUE if successfull, FALSE otherwise (displays error but does not
 *          clean up).
 */
static gboolean
file_utils_copy_file (const gchar* source_file, const gchar* dest_file)
{
  gchar* src_file_content = NULL;
  gsize  src_file_size = 0;
  int    bytes_written = 0;
  FILE*  fd = NULL;
  GError *error;

  // Read file content into memory
  error = NULL;
  g_file_get_contents (source_file, &src_file_content, &src_file_size, &error);
  if (error)
    {
      show_error (_("Error reading file %s: %s"), source_file, error->message);
      g_error_free (error);
      return FALSE;
    }

  // Open destination file
  fd = fopen (dest_file, "wb");
  if (fd == NULL)
    {
      show_error (_("Error opening file %s."), dest_file);
      g_free (src_file_content);
      return FALSE;
    }

  // Write content of src to dst and close it
  bytes_written = fwrite (src_file_content, 1, src_file_size, fd);
  fclose (fd);

  if (bytes_written != src_file_size)
    {
      show_error (_("Error writing to file %s. (%d/%d)"), dest_file, bytes_written, src_file_size);
      g_free (src_file_content);
      return FALSE;
    }
  g_free (src_file_content);

  return TRUE;
}

/**
 * @brief Reads contents from a source file into a destination file
 * @brief and unlinks the source file.
 *
 * The source file is read into memory, so it is inefficient and likely to fail
 * for really big files.
 * If the destination file does exist already, it will be overwritten.
 *
 * @returns TRUE if successfull, FALSE otherwise (displays error but does not
 *          clean up).
 */
static gboolean
file_utils_move_file (const gchar* source_file, const gchar* dest_file)
{
  // Copy file (will displays errors itself)
  if (file_utils_copy_file (source_file, dest_file) == FALSE)
    return FALSE;

  // Remove source file
  if (remove (source_file) != 0)
    {
      show_error (_("Error removing file %s."), source_file);
      return FALSE;
    }

  return TRUE;
}


/* Key creation. */

/**
 * @brief Creates a private key for local checks.
 *
 * Forks and creates a key for local checks by calling
 * "openssl pkcs8 -topk8 -v2 des3 -in filepath -passin pass:passphrase -out
 *          filepath.p8 -passout pass:passphrase"
 * Directories within privkey_file will be created if they do not exist.
 *
 * @param pubkey_file Path to file of public key (a trailing .pub will be stripped).
 * @param privkey_file Name of private key file to be created.
 *
 * @param passphrase_pub The passphrase for the public key.
 * @param passphrase_priv Passhprase for the private key.
 *
 * @return TRUE if successfull, FALSE otherwise.
 */
static gboolean
ssh_privkey_create (char* pubkey_file, char* privkey_file,
                    char* passphrase_pub, char* passphrase_priv)
{
  gchar* astdout = NULL;
  gchar* astderr = NULL;
  GError* err    = NULL;
  gint exit_status;
  gchar* dir = NULL;
  gchar* pubkey_stripped = NULL;

  /* Sanity-check essential parameters */
  if(!passphrase_pub || !passphrase_priv)
    {
      show_error(_("Error creating private key file:\nPlease provide all information."));
      return FALSE;
    }

  /* Sanity check files */
#if 0
  if(check_exists(pubkey_file) != 1)
    {
      show_error(_("Error creating private key file:\nPublic key %s not found."), pubkey_file);
      return FALSE;
    }
  if(check_exists(privkey_file) != 0 )
    {
      show_error(_("Error creating private key file:\nFile already exists."));
      return FALSE;
    }
#else
  if (g_file_test (pubkey_file, G_FILE_TEST_EXISTS) == FALSE)
    {
      show_error(_("Error creating private key file:\nPublic key %s not found."), pubkey_file);
      return FALSE;
    }
  if (g_file_test (privkey_file, G_FILE_TEST_EXISTS))
    {
      show_error(_("Error creating private key file:\nFile already exists."));
      return FALSE;
    }
#endif
  dir = g_path_get_dirname(privkey_file);
#if 0
  if(file_utils_ensure_dir(dir) != TRUE)
    {
      show_error(_("Error creating private key file:\nfolder %s not accessible."), dir);
      g_free (dir);
      return FALSE;
    }
#else
  if (g_mkdir_with_parents (dir, 0755 /* "rwxr-xr-x" */))
    {
      show_error(_("Error creating private key file:\nfolder %s not accessible."), dir);
      g_free (dir);
      return FALSE;
    }
#endif
  g_free (dir);

  // Strip ".pub" of public key filename, if any.
  if (g_str_has_suffix(pubkey_file, ".pub") == TRUE)
    {
      pubkey_stripped = g_malloc (strlen(pubkey_file) -
                                  strlen(".pub") +1); /* RATS: ignore, string literal is nul-terminated */
      g_strlcpy (pubkey_stripped, pubkey_file, strlen(pubkey_file) -
                 strlen(".pub") + 1); /* RATS: ignore, string literal is nul-terminated */
    }
  else
    pubkey_stripped = g_strdup(pubkey_file);

  /* Fire openssl */
  const gchar* command = g_strconcat ("openssl pkcs8 -topk8 -v2 des3 -in ", pubkey_stripped,
                                     " -passin pass:", passphrase_pub, " -out ",
                                     privkey_file, " -passout pass:",
                                     passphrase_priv, NULL);
  g_free (pubkey_stripped);

  if (g_spawn_command_line_sync(command, &astdout, &astderr, &exit_status, &err) == FALSE
      || WIFEXITED (exit_status) == 0
      || WEXITSTATUS (exit_status))
    {
      show_error (_("Error creating private key file.\nFor further information consult your shell."));
      printf ("Error creating private key file.");
      printf ("\tSpawned openssl process returned with %d.\n", exit_status);
      printf ("\t\t stdout: %s\n", astdout);
      printf ("\t\t stderr: %s\n", astderr);
      return FALSE;
    }

  return TRUE;
}

/**
 * Forks and creates a key for local checks by calling
 * "ssh-keygen -t rsa -f filepath -C comment -P passhprase -q"
 * A directory will be created if it does not exist.
 *
 * @param comment Comment to use (will be freed).
 * @param passphrase The passphrase for the key (will be freed), must be longer
 *                   than 4 characters (+nul).
 * @param filepath Path to file of public key (a trailing .pub will be stripped).
 *
 * @return TRUE if successfull, FALSE otherwise.
 */
static gboolean
ssh_pubkey_create (const char* comment, char* passphrase, char* filepath)
{
  gchar* astdout = NULL;
  gchar* astderr = NULL;
  GError* err = NULL;
  gint exit_status = 0;
  gchar* dir;
  gchar* file_pubstripped;

  /* Sanity-check essential parameters */
  if (!comment || comment[0] == '\0')
    {
      show_error (_("Error creating public key file:\ncomment has to be set."));
      return FALSE;
    }
  if (!passphrase || strlen(passphrase) < 5)
    {
      show_error (_("Error creating public key file:\npassword must be longer than 4 characters."));
      return FALSE;
    }
  /* Sanity check files */
  dir = g_path_get_dirname (filepath);
#if 0
  if (file_utils_ensure_dir(dir) != TRUE)
    {
      show_error (_("Error creating public key file:\n%s is not accessable."), filepath);
      g_free (dir);
      return FALSE;
    }
#else
  if (g_mkdir_with_parents (dir, 0755 /* "rwxr-xr-x" */))
    {
      show_error(_("Error creating public key file:\n %s not accessible."), dir);
      g_free (dir);
      return FALSE;
    }
#endif
  g_free (dir);
#if 0
  if (check_exists(filepath) == 1)
  {
    show_error (_("Error creating public key file:\n%s already exists."), filepath);
    return FALSE;
  }
#else
  if (g_file_test (filepath, G_FILE_TEST_EXISTS))
  {
    show_error (_("Error creating public key file:\n%s already exists."), filepath);
    return FALSE;
  }
#endif

  // Strip ".pub" of filename, if any.
  if (g_str_has_suffix(filepath, ".pub") == TRUE)
    {
      file_pubstripped = g_malloc(strlen(filepath) -
                                  strlen(".pub") +1); /* RATS: ignore, string literal is nul-terminated */
      g_strlcpy (file_pubstripped, filepath, strlen(filepath) -
                 strlen(".pub") + 1); /* RATS: ignore, string literal is nul-terminated */
    }
  else
    file_pubstripped = g_strdup(filepath);

  /* Fire ssh-keygen */
  const char* command = g_strconcat("ssh-keygen -t rsa -f ", file_pubstripped, " -C ",
                                    comment, " -P ", passphrase, NULL);
  g_free (file_pubstripped);

  g_debug ("command: %s", command);

  if (g_spawn_command_line_sync(command, &astdout, &astderr, &exit_status, &err) == FALSE
      || WIFEXITED (exit_status) == 0
      || WEXITSTATUS (exit_status))
    {
      // FIX should free err
      show_error (_("Error creating public key file.\nFor further information consult your shell."));
      g_debug ("Error creating public key file.\n");
      g_debug ("\tSpawned key-gen process returned with %d (WIF %i, WEX %i).\n",
               exit_status, WIFEXITED (exit_status), WEXITSTATUS (exit_status));
      g_debug ("\t\t stdout: %s", astdout);
      g_debug ("\t\t stderr: %s", astderr);
      return FALSE;
    }
  return TRUE;
}


/**
 * @brief Creates the public and private key files.
 *
 * @param loginfo.
 * @return TRUE if things went good, FALSE if things went bad.
 */
static gboolean
ssh_key_create (openvas_ssh_login* loginfo)
{
  /* Create pubkey */
  gboolean success = ssh_pubkey_create (loginfo->comment,
                                        loginfo->ssh_key_passphrase,
                                        loginfo->public_key_path);

  /* Eventually report failure */
  if (success == FALSE)
    return FALSE;

  /* Create private key */
  success = ssh_privkey_create (loginfo->public_key_path,
                                loginfo->private_key_path,
                                loginfo->ssh_key_passphrase,
                                loginfo->ssh_key_passphrase);
  return success;
}

/**
 * @brief Unlinks pub. and private key files + identity file.
 *
 * @param loginfo Login of which to unlink files.
 */
static void
ssh_key_create_unlink_files (openvas_ssh_login* loginfo)
{
  char* identity_file = NULL;

  if (loginfo == NULL)
    return;

  // Create identity file path
  if (loginfo->public_key_path != NULL)
    {
      int len = (strlen(loginfo->public_key_path) -
                 strlen (".pub") + 1); /* RATS: ignore, string literal is nul-terminated */
      if (len > 0)
        {
          identity_file = emalloc (len);
          g_strlcpy (identity_file, loginfo->public_key_path, len);
        }

      // Delete all the files
      unlink (identity_file);
      unlink (loginfo->private_key_path);
      unlink (loginfo->public_key_path);
    }

  efree (&identity_file);
}


/* RPM package generation. */

/**
 * @brief Returns the path to the directory where the rpm generator
 * @brief ("openvas-ssh-client-rpm-creator.sh") is located.
 *
 * The search will be performed just once.
 *
 * @return Path to the directory with the rpm generator or NULL (shall not be
 *         freed!).
 */
static gchar*
get_rpm_generator_path ()
{
  static gchar* rpm_generator_path = NULL;

  if (rpm_generator_path == NULL)
    {
      // Search in two location
      gchar* path_exec = g_build_filename ("/home/mattm/share/openvas",
                                           "openvas-ssh-client-rpm-creator.sh",
                                           NULL);
      if (check_is_file (path_exec) == 0)
        {
          g_free (path_exec);
          path_exec = g_build_filename ("tools", "openvas-ssh-client-rpm-creator.sh", NULL);
          if (check_is_file (path_exec) == 0)
            {
              // Could not be found at all
               g_free (path_exec);
            }
          else
            g_free (path_exec);
            // FIX indented with else, should other brn return NULL?
            rpm_generator_path = g_strdup ("tools");
        }
      else
        rpm_generator_path = g_strdup ("/home/mattm/share/openvas");
    }

  return rpm_generator_path;
}

/**
 * @brief Attempts creation of RPM packages to install a users public key file.
 *
 * @param loginfo openvas_ssh_login struct to create rpm for.
 *
 * @return Path to rpm file if successfull, NULL otherwise.
 */
static gboolean
lsc_user_rpm_create (openvas_ssh_login* loginfo, const gchar* to_filename)
{
  // The scripts to create rpms are currently in trunk/tools/openvas-lsc-target-preparation.
  // Move to trunk/openvas-client/tools will be done when function is stable.
  gchar* oltap_path;
  gchar* rpm_path = NULL;
  gint exit_status;
  gchar* new_pubkey_filename = NULL;
  gchar* pubkey_basename = NULL;
  gchar** cmd;
  gchar* tmpdir = NULL;
  gboolean success = TRUE;

  oltap_path = get_rpm_generator_path ();

  /* Create a temporary directory. */

  g_debug ("%s: create temporary directory", __FUNCTION__);
#if 0
  tmpdir = openvas_lsc_target_prep_create_tmp_dir();
  if (tmpdir == NULL)
    {
      return FALSE;
    }
#else /* not 0 */
  // FIX create unique name
  tmpdir = g_build_filename ("/tmp/",
                             "lsc-mngt",
                             "tmp",
                             NULL);
  if (g_mkdir_with_parents (tmpdir, 0755 /* "rwxr-xr-x" */))
    {
      g_free (tmpdir);
      return FALSE;
    }
#endif /* not 0 */
  g_debug ("%s: temporary directory: %s\n", __FUNCTION__, tmpdir);

  /* Copy the public key into the temporary directory. */

  g_debug ("%s: copy key to temporary directory\n", __FUNCTION__);
  pubkey_basename = g_strdup_printf ("%s.pub", loginfo->username);
  new_pubkey_filename = g_build_filename (tmpdir, pubkey_basename, NULL);
  if (file_utils_copy_file (loginfo->public_key_path, new_pubkey_filename) == FALSE)
    {
      show_error ("Could not copy key file %s to %s.",
                  loginfo->public_key_path, new_pubkey_filename);
      g_free (pubkey_basename);
      g_free (new_pubkey_filename);
      g_free (tmpdir);
      return FALSE;
    }

  /* Execute create-rpm script with the temporary directory as the
   * target and the public key in the temporary directory as the key. */

  g_debug ("%s: Attempting RPM build\n", __FUNCTION__);
  cmd = (gchar **) g_malloc (5 * sizeof (gchar *));
  cmd[0] = g_strdup ("./openvas-ssh-client-rpm-creator.sh");
  cmd[1] = g_strdup ("--target");
  cmd[2] = g_strdup (tmpdir);
  cmd[3] = g_build_filename (tmpdir, pubkey_basename, NULL);
  cmd[4] = NULL;
  g_debug ("%s: Spawning in %s: %s %s %s %s\n",
           __FUNCTION__,
           oltap_path, cmd[0], cmd[1], cmd[2], cmd[3]);
  gchar *standard_out;
  gchar *standard_err;
  if (g_spawn_sync (oltap_path,
                    cmd,
                    NULL, // env
                    G_SPAWN_SEARCH_PATH,
                    NULL, // setup func
                    NULL,
                    &standard_out,
                    &standard_err,
                    &exit_status,
                    NULL                 ) == FALSE
      || exit_status != 0)
    {
      show_error(_("Error (%d) creating the rpm.\n"
                   "For further information consult your shell."), exit_status);
      g_debug ("%s: sout: %s\n", __FUNCTION__, standard_out);
      g_debug ("%s: serr: %s\n", __FUNCTION__, standard_err);
      success =  FALSE;
    }

  g_free (cmd[0]);
  g_free (cmd[1]);
  g_free (cmd[2]);
  g_free (cmd[3]);
  g_free (cmd[4]);
  g_free (cmd);
  g_free (pubkey_basename);
  g_free (new_pubkey_filename);
  g_debug ("%s: cmd returned %d.\n", __FUNCTION__, exit_status);

  /* Build the filename that the RPM in the temporary directory has,
   * for example RPMS/noarch/openvas-lsc-target-example_user-0.5-1.noarch.rpm.
   */

  gchar* rpmfile = g_strconcat ("openvas-lsc-target-",
                                loginfo->username,
                                "-0.5-1.noarch.rpm",
                                NULL);
  rpm_path = g_build_filename (tmpdir, rpmfile, NULL);
  g_debug ("%s: new filename (rpm_path): %s\n", __FUNCTION__, rpm_path);

  /* Move the RPM from the temporary directory to the given destination. */

  if (file_utils_move_file (rpm_path, to_filename) == FALSE
      && success == TRUE)
    {
      show_error (_("RPM- File %s couldn't be moved to %s.\nFile will be deleted."),
                  rpm_path, to_filename);
      success = FALSE;
    }

  /* Remove the copy of the public key and the temporary directory. */

  if (file_utils_rmdir_rf (tmpdir) != 0
      && success == TRUE)
    {
      // FIX just make this an error
      show_error (_("Temporary directory (%s) which contains private"
                    "information could not be deleted."),
                  tmpdir);
    }

  g_free (tmpdir);
  g_free (rpm_path);
  g_free (rpmfile);

  return success;
}


/* Deb generation. */

/**
 * @brief Execute alien to create a deb package from an rpm package.
 *
 * @param  rpmdir   Directory to run the command in.
 * @param  rpmfile  .rpm file to transform with alien to a .deb.
 *
 * @return 0 success, -1 error.
 */
static int
execute_alien (const gchar* rpmdir, const gchar* rpmfile)
{
  gchar** cmd;
  gint exit_status = 0;

  /* FIX Why allocate all of this? */
  cmd = (gchar **) g_malloc (7 * sizeof (gchar *));

  cmd[0] = g_strdup ("fakeroot");
  cmd[1] = g_strdup ("--");
  cmd[2] = g_strdup ("alien");
  cmd[3] = g_strdup ("--scripts");
  cmd[4] = g_strdup ("--keep-version");
  cmd[5] = g_strdup (rpmfile);
  cmd[6] = NULL;
  g_debug ("--- executing alien.\n");
  g_debug ("%s: Spawning in %s: %s %s %s %s %s %s\n",
           __FUNCTION__,
           rpmdir, cmd[0], cmd[1], cmd[2], cmd[3], cmd[4], cmd[5]);
  if ((g_spawn_sync (rpmdir,
                     cmd,
                     NULL, // env
                     G_SPAWN_SEARCH_PATH,
                     NULL, // setup func
                     NULL,
                     NULL,
                     NULL,
                     &exit_status,
                     NULL)
       == FALSE)
      || exit_status != 0)
    {
      exit_status = -1;
    }

  g_free (cmd[0]);
  g_free (cmd[1]);
  g_free (cmd[2]);
  g_free (cmd[3]);
  g_free (cmd[4]);
  g_free (cmd[5]);
  g_free (cmd[6]);
  g_free (cmd);

  g_debug ("--- alien returned %d.\n", exit_status);
  return exit_status;
}

/**
 * @brief Create a deb packages from an rpm package.
 *
 * @param  loginfo   openvas_ssh_login struct to create rpm for.
 * @param  rpm_file  location of the rpm file.
 *
 * @return deb package file name on success, else NULL.
 */
gchar*
lsc_user_deb_create (openvas_ssh_login* loginfo,
                     const gchar* rpm_file)
{
  gchar* dirname = g_path_get_dirname (rpm_file);
  gchar* dir = g_strconcat (dirname, "/", NULL);
  gchar* basename = g_path_get_basename (rpm_file);
  gchar* username = g_strdup (loginfo->username ? loginfo->username : "user");
  gchar* deb_name = g_strdup_printf ("%s/openvas-lsc-target-%s_0.5-1_all.deb",
                                     dirname,
                                     g_ascii_strdown (username, -1));

  g_free (dirname);
  g_free (username);

  if (execute_alien (dir, basename))
    {
      g_free (dir);
      g_free (basename);
      g_free (deb_name);
      return NULL;
    }

  g_free (dir);
  g_free (basename);

  return deb_name;
}

/**
 * @brief Returns whether alien could be found in the path.
 *
 * The check itself will only be done once.
 *
 * @return true if alien could be found in the path, false otherwise.
 */
static gboolean
alien_found ()
{
  static gboolean searched = FALSE;
  static gboolean found    = FALSE;

  if (searched == FALSE)
    {
      // Check if alien is found in path
      gchar* alien_path = g_find_program_in_path ("alien");
      if (alien_path != NULL)
        {
          found = TRUE;
          g_free (alien_path);
        }
      searched = TRUE;
    }

  return found;
}


/* Generation of all packages. */

// FIX adapted from openvas-client/src/util/openvas_ssh_key_create.c
/**
 * @brief Create local security check (LSC) packages.
 *
 * @param[in]   name         User name.
 * @param[in]   password     Password.
 * @param[out]  public_key   Public key.
 * @param[out]  private_key  Private key.
 * @param[out]  rpm          RPM package.
 * @param[out]  rpm_size     Size of RPM package, in bytes.
 * @param[out]  deb          Debian package.
 * @param[out]  deb_size     Size of Debian package, in bytes.
 * @param[out]  exe          NSIS package.
 * @param[out]  exe_size     Size of NSIS package, in bytes.
 *
 * @return 0 success, -1 error.
 */
int
lsc_user_all_create (const gchar *name,
                     const gchar *password,
                     gchar **public_key,
                     gchar **private_key,
                     void **rpm, gsize *rpm_size,
                     void **deb, gsize *deb_size,
                     void **exe, gsize *exe_size)
{
  GError *error;
  gsize length;
  char *key_name, *comment, *key_password, *public_key_path;
  char *private_key_path, *user_name, *user_password;
  char rpm_dir[] = "/tmp/rpm_XXXXXX";
  gchar *rpm_path, *deb_path;

  // FIX just skip deb
  if (alien_found () == FALSE)
    return -1;

  // FIX free?
  key_name = estrdup ("key_name");
  comment = estrdup ("comment");
  key_password = estrdup ("password");
  // FIX get temp file
  public_key_path = estrdup ("/tmp/key.pub");
  // FIX get temp file
  private_key_path = estrdup ("/tmp/key.priv");
  user_name = estrdup (name);
  user_password = estrdup (password);

  openvas_ssh_login *login = openvas_ssh_login_new (key_name,
                                                    public_key_path,
                                                    private_key_path,
                                                    key_password,
                                                    comment,
                                                    user_name,
                                                    user_password);

  /* Create keys. */

  ssh_key_create_unlink_files (login);
  if (ssh_key_create (login) == FALSE)
    {
      openvas_ssh_login_free (login);
      return -1;
    }

  /* Create RPM package. */

  // FIX close rpm_dir?
  if (mkdtemp (rpm_dir) == NULL) return -1;
  rpm_path = g_build_filename (rpm_dir, "p.rpm", NULL);
  g_debug ("%s: rpm_path: %s", __FUNCTION__, rpm_path);
  if (lsc_user_rpm_create (login, rpm_path) == FALSE)
    {
      g_free (rpm_path);
      openvas_ssh_login_free (login);
      return -1;
    }

  /* Create Debian package. */

  deb_path = lsc_user_deb_create (login, rpm_path);
  if (deb_path == NULL)
    {
      g_free (rpm_path);
      g_free (deb_path);
      openvas_ssh_login_free (login);
      return -1;
    }
  g_debug ("%s: deb_path: %s", __FUNCTION__, deb_path);

#if 0
  /* Create NSIS installer. */

  exe_path = lsc_user_exe_create (login);
  if (exe_path == NULL)
    {
      g_free (rpm_path);
      g_free (deb_path);
      g_free (exe_path);
      openvas_ssh_login_free (login);
      return -1;
    }
  g_debug ("%s: exe_path: %s", __FUNCTION__, deb_path);
#endif

  error = NULL;
  g_file_get_contents (login->public_key_path,
                       public_key,
                       &length,
                       &error);
  if (error)
    {
      g_free (rpm_path);
      g_free (deb_path);
      g_error_free (error);
      openvas_ssh_login_free (login);
      return -1;
    }

  error = NULL;
  g_file_get_contents (login->private_key_path,
                       private_key,
                       &length,
                       &error);
  if (error)
    {
      g_free (rpm_path);
      g_free (deb_path);
      g_error_free (error);
      openvas_ssh_login_free (login);
      return -1;
    }

  error = NULL;
  g_file_get_contents (rpm_path,
                       (gchar**) rpm,
                       rpm_size,
                       &error);
  // FIX remove rpm file
  g_free (rpm_path);
  if (error)
    {
      g_error_free (error);
      g_free (deb_path);
      openvas_ssh_login_free (login);
      return -1;
    }

  error = NULL;
  g_file_get_contents (deb_path,
                       (gchar**) deb,
                       deb_size,
                       &error);
  // FIX remove deb file (just remove rpm dir)
  g_free (deb_path);
  if (error)
    {
      g_error_free (error);
      openvas_ssh_login_free (login);
      return -1;
    }

  *exe = g_strdup ("");
  *exe_size = 0;

  openvas_ssh_login_free (login);

  return 0;
}
