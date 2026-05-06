-- name: GetDebianTriage :one
SELECT * FROM debian_triage WHERE cve_id = ? LIMIT 1;

-- name: ListDebianTriages :many
SELECT * FROM debian_triage ORDER BY cve_id DESC;

-- name: ListAffectedPackagesForDebianTriage :many
SELECT * FROM debian_triage_affected_package WHERE cve_id = ? ORDER BY id ASC;

-- name: ListAffectedReleasesForDebianTriage :many
SELECT * FROM debian_triage_affected_release WHERE cve_id = ? ORDER BY id ASC;

-- name: InsertDebianPackageOrIgnore :one
INSERT OR IGNORE INTO debian_package(name) VALUES (?) RETURNING *;

-- name: InsertDebianReleaseOrIgnore :one
INSERT OR IGNORE INTO debian_release(name) VALUES (?) RETURNING *;

-- name: InsertDebianTriage :one
INSERT INTO debian_triage(cve_id, status, not_for_us, notes, to_dos) VALUES (?, ?, ?, ?, ?) RETURNING *;

-- name: InsertDebianTriageAffectedPackage :one
INSERT INTO debian_triage_affected_package(cve_id, package_name, version, info) VALUES (?, ?, ?, ?) RETURNING *;

-- name: InsertDebianTriageAffectedRelease :one
INSERT INTO debian_triage_affected_release(cve_id, release_name, package_name, action, info) VALUES (?, ?, ?, ?, ?) RETURNING *;
