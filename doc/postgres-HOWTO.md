# Greenbone-Vulnerability-Manager PostgreSQL backend HOWTO

## Setting up the PostgresSQL database

Please note: Everything should work using Postgres. The reference system used
for development is Debian GNU/Linux 'Stretch' 9.

1.  Install Postgres.

	  (Debian: postgresql, postgresql-contrib, postgresql-server-dev-9.4).

    ```sh
    apt install postgresql postgresql-contrib postgresql-server-dev-all
    ```

2.  Run cmake with this additional parameter:

    ```
    cmake -DBACKEND=POSTGRESQL ...
    ```

3.  Build Manager as usual.

4.  Setup Postgres User and DB (`/usr/share/doc/postgresql-common/README.Debian.gz`)

    ```sh
    sudo -u postgres sh
    createuser -DRS mattm       # mattm is your OS login name
    createdb -O mattm gvmd
    ```

5.  Setup DB extensions and permission.

    ```sh
    sudo -u postgres sh  # if you logged out after step 4
    psql gvmd
    create role dba with superuser noinherit;
    grant dba to mattm;
    create extension "uuid-ossp";
    ```

6.  Make Postgres aware of the gvm libraries if not installed
    in a ld-aware directory. For example create file `/etc/ld.so.conf.d/gvm.conf`
    with appropriate path and then run `ldconfig`.

7.  If you wish to migrate from SQLite, follow the next section before running
    Manager.

8.  Run Manager as usual.

9.  To run SQL on the database.

    ```sh
    psql gvmd
    ```

## Migrating from SQLite to PostgreSQL


1.  Run `gvm-migrate-to-postgres` into a clean newly created PostgreSQL database
    like described above.

    If you accidentally already rebuilt the database or for other reasons
    want to start from scratch, drop the database and repeat the process
    described above.  It is essentially important that you do not start
    Manager before the migration as it would create a fresh one and therefore
    prevent migration.

    Note that the migrate script will modify the SQLite database to clean
    up errors. So it's a good idea to make a backup in case anything goes
    wrong.

2.  Run `greenbone-scapdata-sync`.

3.  Run `greenbone-certdata-sync`.


## Switching between releases

There are two factors for developers to consider when switching between
releases if they are using Postgres as the backend:

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

    Note that for OpenVAS-9 the database name is "tasks", so this step is not
    necessary.


## Analyzing the size of the tables

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
