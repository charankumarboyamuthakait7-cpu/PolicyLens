-- Run this ONCE in MySQL Workbench (or the mysql command line) before starting PolicyLens.
-- It creates an EMPTY database. Do not create tables: `python seed.py init` creates them from the ORM models.
CREATE DATABASE IF NOT EXISTS policylens_db
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
