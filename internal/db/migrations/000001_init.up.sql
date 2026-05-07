BEGIN;

CREATE TABLE IF NOT EXISTS cve(
    id TEXT PRIMARY KEY,
    title TEXT,
    description TEXT,
    serial INTEGER NOT NULL DEFAULT 1,
    is_rejected INTEGER NOT NULL DEFAULT 0,
    assigner_org_id TEXT,
    assigner_short_name TEXT,
    date_reserved TEXT,
    date_published TEXT,
    date_updated TEXT,
    date_assigned TEXT,
    date_public TEXT
);

CREATE TABLE IF NOT EXISTS product(
    id INTEGER PRIMARY KEY,
    title TEXT,
    cpe TEXT
);

CREATE TABLE IF NOT EXISTS affect(
    id INTEGER PRIMARY KEY,
    cve_id TEXT,
    product_id INTEGER,
    FOREIGN KEY(cve_id) REFERENCES cve(id),
    FOREIGN KEY(product_id) REFERENCES product(id)
);

CREATE TABLE IF NOT EXISTS cvss_metric(
    id INTEGER PRIMARY KEY,
    cve_id TEXT,
    issuer TEXT,
    version TEXT,
    vector_string TEXT,
    base_score REAL,
    base_severity TEXT,
    FOREIGN KEY(cve_id) REFERENCES cve(id)
);

CREATE TABLE IF NOT EXISTS debian_triage(
    cve_id TEXT PRIMARY KEY,
    status TEXT CHECK( status IN ('UNKNOWN', 'TODO', 'REJECTED', 'NOT-FOR-US', 'PROCESSED', 'RESERVED') ) NOT NULL,
    not_for_us TEXT NOT NULL,
    notes TEXT NOT NULL,
    to_dos TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS debian_package(
    name TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS debian_triage_affected_package(
    id INTEGER PRIMARY KEY,
    cve_id TEXT NOT NULL,
    package_name TEXT NOT NULL,
    version TEXT NOT NULL,
    info TEXT,
    FOREIGN KEY(cve_id) REFERENCES debian_triage(cve_id),
    FOREIGN KEY(package_name) REFERENCES debian_package(name)
);

CREATE TABLE IF NOT EXISTS debian_release(
    name TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS debian_triage_affected_release(
    id INTEGER PRIMARY KEY,
    cve_id TEXT NOT NULL,
    release_name TEXT NOT NULL,
    package_name TEXT NOT NULL,
    action TEXT NOT NULL,
    info TEXT,
    FOREIGN KEY(cve_id) REFERENCES debian_triage(cve_id),
    FOREIGN KEY(release_name) REFERENCES debian_release(name)
);

END;
