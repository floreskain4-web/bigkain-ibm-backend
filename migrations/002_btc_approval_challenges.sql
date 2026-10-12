CREATE TABLE IF NOT EXISTS public.bigkain_btc_approval_challenges (
  challenge_id text PRIMARY KEY
    CHECK (challenge_id ~ '^bk_ch_[0-9a-f]{32}$'),
  wallet_address text NOT NULL,
  message_sha256 text NOT NULL
    CHECK (message_sha256 ~ '^[0-9a-f]{64}$'),
  transaction_commitment text NOT NULL
    CHECK (transaction_commitment ~ '^[0-9a-f]{64}$'),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  approval_id text UNIQUE
    CHECK (approval_id IS NULL OR approval_id ~ '^bk_txapp_[0-9a-f]{32}$'),
  approved_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT bigkain_btc_approval_challenge_approved_after_consumed_check
    CHECK (approved_at IS NULL OR consumed_at IS NOT NULL),
  CONSTRAINT bigkain_btc_approval_challenge_id_timestamp_pair_check
    CHECK ((approval_id IS NULL) = (approved_at IS NULL))
);

CREATE INDEX IF NOT EXISTS bigkain_btc_approval_challenges_expires_idx
  ON public.bigkain_btc_approval_challenges (expires_at);

CREATE INDEX IF NOT EXISTS bigkain_btc_approval_challenges_approved_idx
  ON public.bigkain_btc_approval_challenges (approved_at DESC)
  WHERE approved_at IS NOT NULL;

GRANT USAGE ON SCHEMA public TO bigkain_ownership_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE
  ON TABLE public.bigkain_btc_approval_challenges
  TO bigkain_ownership_runtime;
