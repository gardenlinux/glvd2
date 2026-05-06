-- name: ListCVEs :many
SELECT * FROM cve ORDER BY name DESC;
