-- Run as cluster administrator using psql variables; passwords must not be command-line arguments.
SELECT format('CREATE ROLE patch_owner LOGIN PASSWORD %L', :'owner_password') WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='patch_owner') \gexec
SELECT format('CREATE ROLE patch_writer LOGIN PASSWORD %L', :'writer_password') WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='patch_writer') \gexec
SELECT format('CREATE ROLE patch_reader LOGIN PASSWORD %L', :'reader_password') WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='patch_reader') \gexec
SELECT 'CREATE DATABASE patch_intelligence OWNER patch_owner' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname='patch_intelligence') \gexec
REVOKE ALL ON DATABASE patch_intelligence FROM PUBLIC;
GRANT CONNECT ON DATABASE patch_intelligence TO patch_owner,patch_writer,patch_reader;
\connect patch_intelligence
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO patch_writer,patch_reader;
ALTER DEFAULT PRIVILEGES FOR ROLE patch_owner IN SCHEMA public GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO patch_writer;
ALTER DEFAULT PRIVILEGES FOR ROLE patch_owner IN SCHEMA public GRANT SELECT ON TABLES TO patch_reader;
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO patch_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO patch_reader;
ALTER ROLE patch_reader SET default_transaction_read_only=on;
ALTER ROLE patch_reader SET statement_timeout='15s';
ALTER ROLE patch_writer SET statement_timeout='120s';
