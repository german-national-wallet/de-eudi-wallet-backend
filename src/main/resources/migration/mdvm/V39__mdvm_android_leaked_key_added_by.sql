ALTER TABLE mdvm_android_leaked_key
    ADD COLUMN added_by TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE mdvm_android_leaked_key
    ALTER COLUMN added_by DROP DEFAULT;
