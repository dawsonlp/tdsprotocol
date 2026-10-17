-- Database existence belongs to environment setup, independent of pytest order.
-- Repeated Compose starts preserve the existing database and its contents.
IF DB_ID(N'tds_test') IS NULL
    CREATE DATABASE tds_test;
GO
