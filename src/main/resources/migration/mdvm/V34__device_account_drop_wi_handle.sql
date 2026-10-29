CREATE UNIQUE INDEX device_account_auth_pubk_der ON device_account (wi_mdvm_auth_pubk_der);

ALTER TABLE device_account
    DROP COLUMN wi_handle;
