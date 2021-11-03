# INSTALLATION INSTRUCTIONS FOR GREENBONE VULNERABILITY MANAGER

Please note: The reference system used by most of the developers is Debian
GNU/Linux 'Buster' 10. The build might fail on any other system. Also, it is
necessary to install dependent development packages.

## Prerequisites for Greenbone Vulnerability Manager

Prerequisites:
* GCC (Debian package: gcc)
* cmake >= 3.0 (Debian package: cmake)
* glib-2.0 >= 2.42 (Debian package: libglib2.0-dev)
* gnutls >= 3.2.15 (Debian package: libgnutls28-dev)
* libgvm_base, libgvm_util, libgvm_osp, libgvm_gmp >= 21.4.1 ([gvm-libs](https://github.com/greenbone/gvm-libs/tree/stable) component)
* PostgreSQL database >= 9.6 (Debian packages: libpq-dev postgresql-server-dev-11)
* pkg-config (Debian package: pkg-config)
* libical >= 1.0.0 (Debian package: libical-dev)
* xsltproc (Debian package: xsltproc)
* gpgme

Install these prerequisites on Debian GNU/Linux 'Buster' 10:

    apt-get install gcc cmake libglib2.0-dev libgnutls28-dev libpq-dev postgresql-server-dev-11 pkg-config libical-dev xsltproc libgpgme-dev

Prerequisites for building documentation:
* Doxygen
* xsltproc (for building the GMP HTML documentation)
* xmltoman (optional, for building man page)

Prerequisites for building tests:
* Cgreen (optional, for building tests)

Please see the section "Prerequisites for Optional Features" below additional
optional prerequisites.


## Compiling Greenbone Vulnerability Manager

If you have installed required libraries to a non-standard location, remember to
set the `PKG_CONFIG_PATH` environment variable to the location of you pkg-config
files before configuring:

    export PKG_CONFIG_PATH=/your/location/lib/pkgconfig:$PKG_CONFIG_PATH

Create a build directory and change into it with:

    mkdir build
    cd build

Then configure the build with:

    cmake -DCMAKE_INSTALL_PREFIX=/path/to/your/installation ..

Or (if you want to use the default installation path `/usr/local/`):

    cmake ..

This only needs to be done once.

Thereafter, the following commands are useful:

    make                # build the scanner
    make doc            # build the documentation
    make doc-full       # build more developer-oriented documentation
    make tests          # build tests
    make install        # install the build
    make rebuild_cache  # rebuild the cmake cache

Please note that you may have to execute `make install` as root, especially if
you have specified a prefix for which your user does not have full permissions.

To clean up the build environment, simply remove the contents of the `build`
directory you created above.


## Choosing the Connection Type

Greenbone Vulnerability Manager can serve client connections on either a TCP
socket or a UNIX domain socket.

The default is a UNIX domain socket at:

    <install-prefix>/var/run/gvmd.sock

This location can be overridden with the `--unix-socket` option, and the
permissions of the socket can be specified with the `--listen-owner`,
`--listen-group` and `--listen-mode` options.

To use a TCP socket, call gvmd with the --listen option, for example:

    gvmd --listen=127.0.0.1


## Certificate Generation

All TCP-based communication with Greenbone Vulnerability Manager uses the TLS
protocol to establish secure connections and for authentication and
authorization.  This requires the presence of a certificate infrastructure
consisting of a certificate authority (CA) and a server and client certificate
signed by the CA.

Greenbone Vulnerability Manager uses a client certificate when connecting to
a scanner via the OSP protocol.

The easiest way to generate this certificate is to use the
`gvm-manage-certs` script. A quick way to set up required certificates
on the local system is to execute the command `gvm-manage-certs -a`.

If you intend to use OSP scanners and Manager on separate systems you need to make
sure that the mutual trust is properly configured via the TLS certificates.
The `gvm-manage-certs` script can assist you in setting up your infrastructure.
Please refer to the documentation provided with the script for usage details.

If certificates have expired or in other ways there is need to update
certificates for scanners, please see also section `Updating Scanner
Certificates`.


## Configure PostgreSQL Database Backend

### Setting up the PostgreSQL database

1.  Install Postgres.

    ```sh
    apt install postgresql postgresql-contrib postgresql-server-dev-all
    ```

2.  Run cmake and build gvmd as usual.

3.  Setup Postgres User and DB (`/usr/share/doc/postgresql-common/README.Debian.gz`)

    ```sh
    sudo -u postgres bash
    createuser -DRS mattm       # mattm is your OS login name
    createdb -O mattm gvmd
    ```

4.  Setup permissions.

    ```sh
    sudo -u postgres bash  # if you logged out after step 3
    psql gvmd
    create role dba with superuser noinherit;
    grant dba to mattm;    # mattm is the user created in step 3
    ```

5.  Make Postgres aware of the gvm libraries if not installed
    in a ld-aware directory. For example create file `/etc/ld.so.conf.d/gvm.conf`
    with appropriate path and then run `ldconfig`.

6.  Run Manager as usual.

7. To run SQL on the database.

    ```sh
    psql gvmd
    ```

### Switching between releases

There are two factors for developers to consider when switching between
releases:

1.  gvmd uses C server-side extensions that link to gvm-libs, so Postgres
    needs to be able to find the version of gvm-libs that goes with gvmd.

    One way to do this is to modify `ld.so.conf` and run `ldconfig` after
    installing the desired gvmd version.

2.  The Postgres database "gvmd" must be the version that is supported by
    gvmd. If it is too high, gvmd will refuse to run.  If it is too low
    gvmd will only run if the database is migrated to the higher version.

    One way to handle this is to switch between different versions of the
    database using RENAME:

    ```sh
    sudo -u postgres psql -q --command='ALTER DATABASE gvmd RENAME TO gvmd_10;'
    sudo -u postgres psql -q --command='ALTER DATABASE gvmd_master RENAME TO gvmd;'
    ```

### Analyzing the size of the tables

In case the database grows in size and you want to understand
which of the tables is responsible for it, there are two queries
to check table sizes:

Biggest relations:

```sql
SELECT nspname || '.' || relname AS "relation",
    pg_size_pretty(pg_relation_size(C.oid)) AS "size"
  FROM pg_class C
  LEFT JOIN pg_namespace N ON (N.oid = C.relnamespace)
  WHERE nspname NOT IN ('pg_catalog', 'information_schema')
  ORDER BY pg_relation_size(C.oid) DESC
  LIMIT 20;
```

Biggest tables:

```sql
SELECT nspname || '.' || relname AS "relation",
    pg_size_pretty(pg_total_relation_size(C.oid)) AS "total_size"
  FROM pg_class C
  LEFT JOIN pg_namespace N ON (N.oid = C.relnamespace)
  WHERE nspname NOT IN ('pg_catalog', 'information_schema')
    AND C.relkind <> 'i'
    AND nspname !~ '^pg_toast'
  ORDER BY pg_total_relation_size(C.oid) DESC
  LIMIT 20;
```

These queries were taken from https://wiki.postgresql.org/wiki/Disk_Usage


## Migrating the Database (e.g. during an upgrade of GVM)

If you have used Manager before (e.g. an older version which got upgraded to
a newer major release), you might get the following error in your `gvmd.log`
during startup:

    gvmd: database is wrong version

If this is happening you need to migrate the database to the current data model.
Use this command to run the migration:

    gvmd --migrate


## Creating an administrator user for GVM

You can create an administrator user with the `--create-user` option of `gvmd`:

    gvmd --create-user=myuser

The new user's password is printed on success.

An administrator user can later create further users or administrators via
clients like the Greenbone Security Assistant (GSA).

Also, the new user can change their password via GSA.


## Set the Feed Import Owner

Certain resources that were previously part of the gvmd source code are now
shipped via the feed.  An example is the config "Full and Fast".

gvmd will only create these resources if a "Feed Import Owner" is configured:

    gvmd --modify-setting 78eceaec-3385-11ea-b237-28d24461215b --value <uuid_of_user>

The UUIDs of all created users can be found using

    gvmd --get-users --verbose


## Keeping the feeds up-to-date

The `gvmd Data`, `SCAP` and `CERT` Feeds should be kept up-to-date by calling the
`greenbone-feed-sync` script regularely (e.g. via a cron entry):

    greenbone-feed-sync --type GVMD_DATA
    greenbone-feed-sync --type SCAP
    greenbone-feed-sync --type CERT

Please note: The `CERT` feed sync depends on data provided by the `SCAP` feed
and should be called after syncing the latter.


## Configure the default OSPD scanner socket path

By default, Manager tries to connect to the default OSPD scanner via the following path:

    /var/run/ospd/ospd.sock

If this path doesn't match your setup you need to change the socket path accordingly.

Get the UUID of the `OpenVAS Default` scanner:

    gvmd --get-scanners

Update the path (example, path needs to be adapted accordingly):

    gvmd --modify-scanner=<uuid of OpenVAS Default scanner> --scanner-host=<install-prefix>/var/run/ospd/ospd-openvas.sock


## Logging Configuration

By default, Manager writes logs to the file

    <install-prefix>/var/log/gvm/gvmd.log

Logging is configured entirely by the file

    <install-prefix>/etc/gvm/gvmd_log.conf

The configuration is divided into domains like this one

    [md   main]
    prepend=%t %p
    prepend_time_format=%Y-%m-%d %Hh%M.%S %Z
    file=/var/log/gvm/gvmd.log
    level=128

The `level` field controls the amount of logging that is written.
The value of `level` can be

      4  Errors.
      8  Critical situation.
     16  Warnings.
     32  Messages.
     64  Information.
    128  Debug.  (Lots of output.)

Enabling any level includes all the levels above it. So enabling Information
will include Warnings, Critical situations and Errors.

To get absolutely all logging, set the level to 128 for all domains in the
configuration file.

Logging to `syslog` can be enabled in each domain like:

    [md   main]
    prepend=%t %p
    prepend_time_format=%Y-%m-%d %Hh%M.%S %Z
    file=syslog
    syslog_facility=daemon
    level=128


## Optimizing the database

Greenbone Vulnerability Manager offers the command line option
`--optimize=<name>` to run various optimization of the database. The currently
supported values for `<name>` are:

- `vacuum`

  This option can reduce the file size by freeing some unused storage
  space in the database.
  For more information see the documentation for the `VACUUM` command of the
  database back-end you are using.

- `analyze`

  This option updates various internal statistics of the database used to
  optimize queries.
  For more information see the documentation for the `ANALYZE` command of the
  database back-end you are using.

- `add-feed-permissions`

  This option adds new read permissions on all feed data objects for the roles
  defined in the "Feed Import Roles" setting if they do not exist.
  The new permissions will be owned by the same user as the data objects,
  usually the feed import owner.

  This does not affect the command permissions, any permissions created for
  users or groups, or other types of permissions like modify or delete.

- `cleanup-config-prefs`

  This option removes duplicate preferences from Scan Configs and corrects
  some broken preference values.  For the latter, the NVT preferences in the
  database must be up to date (if Manager and Scanner are both running, then
  this should happen automatically).

- `cleanup-feed-permissions`

  This option removes permissions on all feed data objects for all roles
  that are not defined in the "Feed Import Roles" setting.

  This does not affect the command permissions, any permissions created for
  users or groups, or other types of permissions like modify or delete.

- `cleanup-port-names`

  This cleans up the ports of results as stored in the database by removing
  parts that do not conform to the format `<port>/<protocol>`.
  For example the application name will be removed from a port using the old
  format `telnet (23/tcp)`, reducing it to the new format `23/tcp`.
  This makes filtering results and delta reports more consistent.

- `cleanup-report-formats`

  This cleans up references to report formats that have been removed without
  using the DELETE_REPORT_FORMAT GMP command, for example after a built-in
  report format has been removed.

- `cleanup-result-nvts`

  This cleans up results with missing result_nvt entries which can result
  in filters and overrides not working properly.

- `cleanup-result-severities`

  This cleans up results with no severity by assigning the default
  severity set by the user owning the result.
  All new results should have a severity assigned but this was not ensured in
  older versions, so this function can be used to correct missing severity
  scores in older reports.

- `migrate-relay-sensors`

  If relays are active, this can be used to make sure all sensor type
  scanners have a matching relay, i.e. OSP sensors have an OSP relay
  and GMP scanners have a GMP relay.
  GMP scanners are migrated to OSP sensors if an OSP relay is available.

- `rebuild-report-cache`

  This clears the cache containing the unfiltered result counts of all reports
  and fully rebuilds it.

- `update-report-cache`

  This creates the cache containing the unfiltered result counts of all reports
  that are not cached yet.


## Encrypted Credentials

By default, the Manager stores private key and password parts of target
credentials encrypted in the database.  This avoids leaking such keys
via backups.  To be able to do a proper restore of the data, it is
important to also backup the encryption key.  The easiest way to do
this is to create backup of the entire directory tree

    <install-prefix>/var/lib/gvm/gvmd/gnupg/

and store it at a safe place independent of the database backups.
This needs to be done only once after the key has been created or
changed.  The Manager creates the key at startup if it does not
exist.

To check whether the key has been generated you may use the command:

    gpg --homedir <install-prefix>/var/lib/gvm/gvmd/gnupg --list-secret-keys

An example output would be:

    sec   2048R/1B55390F 2013-01-18
    uid                  GVM Credential Encryption

Your key will have the same user ID (`GVM Credential Encryption`)
but another keyid (1B55390F) and another creation date (2013-01-18).

Older versions of the Manager didn't used encrypted credentials.  Thus,
for old installations the database may hold a mix of cleartext and
encrypted credentials.  Note, that after changing a cleartext
credential it will be saved encrypted.

To encrypt all existing credentials you may use:

    gvmd --encrypt-all-credentials

Key change: If you disable the current key (see also the gpg manual) and
create a new key, this command will decrypt using the old but disabled key
and then re-encrypt using the new key.  The command `--decrypt-all-credentials`
may be used to revert to plaintext credentials:

    gpg --homedir /var/lib/gvm/gvmd/gnupg -K

Look for the current key and remember its keyid. Then:

    gpg --homedir /var/lib/gvm/gvmd/gnupg --edit-key KEYID

At the prompt enter `disable` followed by `save` and `quit`.
Then create a new key and re-encrypt all passwords:

    gvmd --create-credentials-encryption-key
    gvmd --encrypt-all-credentials

No encryption: If for backward compatibility reasons encrypted credentials
are not desired, the manager must _always_ be started with the option
`--disable-encrypted-credentials`.


## Resetting Credentials Encryption Key

If you lost some part of the encryption key, neither a regular migration nor
a simple creation might work.

In this case you need to reset the encryption key with the following
procedure. There is no way to get the encrypted credentials back. You
will need to enter all of them anew afterwards.

Get the key fingerprint:

    gpg --homedir <install-prefix>/var/lib/gvm/gvmd/gnupg --list-secret-keys

Remove the secret key:

    gpg --homedir=<prefix>/etc/openvas/gnupg --delete-secret-keys KEYID

Remove the key:

    gpg --homedir=<prefix>/etc/openvas/gnupg --delete-keys KEYID

Create a new key:

    gvmd --create-credentials-encryption-key

Finally, reset all credentials, by hand.


## Updating Scanner Certificates

If you have changed the CA certificate used to sign the server and client
certificates or the client certificate itself you will need to update the
certificates in Manager database as well.

The database can be updated using the following command:

    gvmd --modify-scanner <uuid> \
         --scanner-ca-pub <cacert> \
         --scanner-key-pub <clientcert> \
         --scanner-key-priv <clientkey>

Where:
- `<uuid>`

  refers to the UUID used by OpenVAS Manager to identify the scanner;
  the UUID can be retrieved with `gvmd --get-scanners`.

- `<cacert>`

  refers to the certificate of the CA used to sign the scanner certificate.
  Leaving this empty will delete the CA certificate of the scanner. This option
  can be dropped if the scanner uses a certificate that corresponds with the
  default CA certificate of Manager.

- `<clientcert>`

  refers to the certificate Manager uses to authenticate when
  connecting to the scanner. For a default OSP scanner setup
  with self-signed certificates this would be
  `/var/lib/gvm/CA/clientcert.pem`.

- `<clientkey>`
  refers to the private key Manager uses to authenticate when
  connecting to the scanner. For a default OSP scanner setup
  with self-signed certificates this would be
  `/var/lib/gvm/private/CA/clientkey.pem`.

To set just a new default CA certificate:

    gvmd --modify-setting 9ac801ea-39f8-11e6-bbaa-28d24461215b \
         --value "`cat /var/lib/gvm/CA/cacert.pem`"

Replace the path to the pem-file with the one of your setup. The
UUID is the fixed one of the immutable global setting for the default
CA certificate and thus does not need to be changed.


## Changing the Maximum Number of Rows per Page

The maximum number of rows returned by the GMP `GET` commands, like `GET_TARGETS`,
is controlled by the GMP setting "Max Rows Per Page".  This setting is an upper
limit on the number of resources returned by any `GET` command, regardless of the
value given for `rows` in the command's filter.

The default value for "Max Rows Per Page" is 1000.  0 indicates no limit.

This setting can not be changed via GMP.  However, the gvmd option
`--modify-setting` can be used to change it.

    gvmd --modify-setting 76374a7a-0569-11e6-b6da-28d24461215b \
        --value 100

This changes the global value of the setting, and so applies to all users.
Adding `--user` to the command will set a value for maximum rows only for that
user.


## Prerequisites for Optional Features

Certain features of the Manager also require some programs at run time:

Prerequisites for generating PDF reports:
* pdflatex

  On Debian GNU/Linux 'Stretch' 9 the following packages can be installed to
  fulfill this prerequisite:

      apt-get install texlive-latex-extra --no-install-recommends
      apt-get install texlive-fonts-recommended

Prerequisites for generating HTML reports:
* xsltproc

Prerequisites for generating verinice reports:
* xsltproc, xmlstarlet, zip

Prerequisites for generating credential RPM packages:
* rpm
* fakeroot

Prerequisites for generating credential DEB packages:
* dpkg
* fakeroot

Prerequisites for generating credentials .exe packages:
* makensis (usually distributed as part of nsis)

Prerequisites for generating system reports:
* A program in the `PATH`, with usage `gvmcg seconds type`, where
  seconds is the number of seconds before now that the report covers,
  and type is the type of report.  When called with type `titles` the
  script must print a list of possible types, where the name of the
  type is everything up to the first space and everything else is a
  title for the report.  When called with one of these types, `gvmcg`
  must print a PNG in base64 encoding.  When called with the special
  type `blank`, gvmcg must print a PNG in base64 for the Manager to
  use when a request for one of the titled types fails. `gvmcg` may
  indicate failure by simply refraining from printing.

Prerequisites for signature verification:
* gnupg

Prerequisites for HTTP alerts:
* wget

Prerequisites for Alemba vFire alert:
* A program in the `PATH` called `greenbone_vfire_connector` that takes the
  path to an XML file as described by doc/vfire-data-xml.rnc as an argument.

Prerequisites for Sourcefire Connector alert:
* A program in the `PATH` called `greenbone_sourcefire_connector` that takes
  args IP, port, PKCS12 file and report file in Sourcefire format.

Prerequisites for verinice .PRO Connector alert:
* A program in the `PATH` called `greenbone_verinice_connector` that takes args
  IP, port, username, password and report file in verinice .PRO format.

Prerequisites for SCP alert:
* sshpass
* scp

Prerequisites for Send alert:
* socat

Prerequisites for SNMP alert:
* snmp

Prerequisites for SMB alert:
* python3
* smbclient

Prerequisites for Tipping Point alert:
* python3
* python3-lxml

Prerequisites for key generation on systems with low entropy:
* haveged (or a similar tool)

Prerequisites for S/MIME support (e.g. email encryption):
* GNU privacy guard - S/MIME version (Debian package: gpgsm)

Prerequisites for certificate generation:
* GnuTLS certtool (Debian package: gnutls-bin)

Prerequisites (recommended) to lower sync RAM usage
* xml_split (Debian package: xml-twig-tools)

## Static code analysis with the Clang Static Analyzer

If you want to use the Clang Static Analyzer (https://clang-analyzer.llvm.org/)
to do a static code analysis, you can do so by prefixing the configuration and
build commands with `scan-build`:

    scan-build cmake ..
    scan-build make

The tool will provide a hint on how to launch a web browser with the results.

It is recommended to do this analysis in a separate, empty build directory and
to empty the build directory before `scan-build` call.
