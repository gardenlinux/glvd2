-- name: ListCves :many
SELECT sqlc.embed(c) FROM cve As c ORDER BY c.name DESC;
