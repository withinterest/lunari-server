CREATE TABLE purchase_claims (
  token_hash CHAR(64) PRIMARY KEY,
  package_name TEXT NOT NULL,
  product_id TEXT NOT NULL,
  claimant_id VARCHAR(128) NOT NULL,
  grant_stars INTEGER NOT NULL CHECK (grant_stars > 0),
  purchase_state TEXT NOT NULL CHECK (purchase_state = 'PURCHASED'),
  google_order_id TEXT NULL,
  claim_id UUID NOT NULL UNIQUE,
  granted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT purchase_claims_token_hash_format
    CHECK (token_hash ~ '^[0-9a-f]{64}$')
);

CREATE INDEX purchase_claims_claimant_id_idx
  ON purchase_claims (claimant_id);
