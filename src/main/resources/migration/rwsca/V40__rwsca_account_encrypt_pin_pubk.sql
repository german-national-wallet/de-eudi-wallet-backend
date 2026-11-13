DELETE FROM rwsca_account;

ALTER TABLE rwsca_account
    DROP CONSTRAINT rwsca_pin_pubk_and_counter_null_together,
    DROP CONSTRAINT rwsca_pin_failed_at_requires_pin,
    DROP COLUMN wi_rwsca_pin_pubk_der,
    ADD COLUMN wi_rwsca_pin_pubk_key_id TEXT,
    ADD COLUMN wi_rwsca_pin_pubk_iv BYTEA,
    ADD COLUMN wi_rwsca_pin_pubk_ct BYTEA,
    ADD COLUMN wi_rwsca_pin_pubk_tag BYTEA,
    ADD CONSTRAINT rwsca_pin_pubk_all_or_nothing
        CHECK (num_nulls(wi_rwsca_pin_pubk_key_id, wi_rwsca_pin_pubk_iv, wi_rwsca_pin_pubk_ct, wi_rwsca_pin_pubk_tag)
            IN (0, 4)),
    ADD CONSTRAINT rwsca_pin_pubk_and_counter_null_together
        CHECK ((wi_rwsca_pin_pubk_key_id IS NULL) = (rwsca_pin_try_counter IS NULL)),
    ADD CONSTRAINT rwsca_pin_failed_at_requires_pin
        CHECK (wi_rwsca_pin_pubk_key_id IS NOT NULL OR rwsca_pin_try_failed_at IS NULL);
