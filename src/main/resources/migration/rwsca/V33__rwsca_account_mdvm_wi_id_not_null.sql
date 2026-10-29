DELETE
FROM rwsca_account
WHERE mdvm_wi_id IS NULL;
ALTER TABLE rwsca_account
    ALTER COLUMN mdvm_wi_id SET NOT NULL;
