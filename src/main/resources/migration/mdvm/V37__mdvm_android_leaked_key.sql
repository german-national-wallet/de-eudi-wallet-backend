CREATE TABLE mdvm_android_leaked_key
(
    serial     TEXT PRIMARY KEY,
    status     TEXT        NOT NULL,
    reason     TEXT        NOT NULL,
    comment    TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
