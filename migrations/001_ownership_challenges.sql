CREATE TABLE IF NOT EXISTS public.bigkain_ownership_challenges (
  challenge_id text PRIMARY KEY
    CHECK (challenge_id ~ '^bk_gpt_ch_[0-9a-f]{32}$'),
  address text NOT NULL,
  message_sha256 text NOT NULL
    CHECK (message_sha256 ~ '^[0-9a-f]{64}$'),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  verified_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT bigkain_ownership_verified_after_consumed_check
    CHECK (verified_at IS NULL OR consumed_at IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS bigkain_ownership_challenges_expires_idx
  ON public.bigkain_ownership_challenges (expires_at);

CREATE INDEX IF NOT EXISTS bigkain_ownership_challenges_verified_idx
  ON public.bigkain_ownership_challenges (verified_at DESC)
  WHERE verified_at IS NOT NULL;

GRANT USAGE ON SCHEMA public TO bigkain_ownership_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE
  ON TABLE public.bigkain_ownership_challenges
  TO bigkain_ownership_runtime;
