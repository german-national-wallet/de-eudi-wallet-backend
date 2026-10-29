DELETE
FROM wpb_account
WHERE mdvm_wi_id IS NULL;
ALTER TABLE wpb_account
    ALTER COLUMN mdvm_wi_id SET NOT NULL;
