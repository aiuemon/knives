-- name: RecordAuditLog :exec
INSERT INTO audit_log (actor_user_id, action, target_type, target_id, metadata)
VALUES ($1, $2, $3, $4, $5);
