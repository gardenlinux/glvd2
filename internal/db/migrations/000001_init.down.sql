BEGIN;

DROP TABLE IF EXISTS cve;
DROP TABLE IF EXISTS product;
DROP TABLE IF EXISTS affect;
DROP TABLE IF EXISTS cvss_metric;

DROP TABLE IF EXISTS debian_triage;
DROP TABLE IF EXISTS debian_package;
DROP TABLE IF EXISTS debian_triage_affected_package;
DROP TABLE IF EXISTS debian_release;
DROP TABLE IF EXISTS debian_triage_affected_release;

END;
