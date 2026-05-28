BEGIN;

CREATE TABLE IF NOT EXISTS repo_metadata (
    repo TEXT NOT NULL, 
    branch TEXT NOT NULL, 
    data JSONB,
    commitid TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),

    PRIMARY KEY(repo, branch)
);

COMMIT;
