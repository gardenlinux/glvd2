BEGIN;

CREATE TABLE IF NOT EXISTS cve(
    id TEXT PRIMARY KEY,
    title TEXT,
    description TEXT,
    serial INT NOT NULL DEFAULT 1,
    is_rejected INT NOT NULL DEFAULT 0,
    assigner_org_id TEXT,
    assigner_short_name TEXT,
    date_reserved TEXT,
    date_published TEXT,
    date_updated TEXT,
    date_assigned TEXT,
    date_public TEXT
);

CREATE TABLE IF NOT EXISTS product(
    id INT PRIMARY KEY,
    title TEXT,
    cpe TEXT
);

CREATE TABLE IF NOT EXISTS affect(
    id INT PRIMARY KEY,
    cve_id TEXT,
    FOREIGN KEY(cve_id) REFERENCES cve(id),
    FOREIGN KEY(product_id) REFERENCES product(id)
);

CREATE TABLE IF NOT EXISTS cvss_metric(
    id INT PRIMARY KEY,
    cve_id TEXT,
    issuer TEXT,
    version TEXT,
    vector_string TEXT,
    base_score REAL,
    base_severity TEXT,
    FOREIGN KEY(cve_id) REFERENCES cve(id)
);

END;
