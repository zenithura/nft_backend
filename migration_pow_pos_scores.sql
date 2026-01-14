-- ============================================================================
-- MIGRATION: Create PoW/PoS Scores Table
-- ============================================================================
-- Purpose: Store Proof of Work and Proof of Stake scores for users
-- Run this in Supabase SQL Editor
-- ============================================================================

-- PoW/PoS Scores table
CREATE TABLE IF NOT EXISTS user_pow_pos_scores (
    score_id BIGSERIAL PRIMARY KEY,
    wallet_id BIGINT REFERENCES wallets(wallet_id) ON DELETE CASCADE,
    wallet_address VARCHAR(255) NOT NULL,
    
    -- Proof of Work (Activity-based)
    pow_score NUMERIC(18, 2) DEFAULT 0.0,
    pow_tickets_purchased INTEGER DEFAULT 0,
    pow_events_attended INTEGER DEFAULT 0,
    pow_marketplace_txns INTEGER DEFAULT 0,
    pow_referrals INTEGER DEFAULT 0,
    pow_last_activity_date DATE,
    
    -- Proof of Stake (Economic stake)
    pos_score NUMERIC(18, 2) DEFAULT 0.0,
    pos_nft_tickets_held INTEGER DEFAULT 0,
    pos_wallet_balance_eth NUMERIC(18, 8) DEFAULT 0.0,
    pos_days_active INTEGER DEFAULT 0,
    pos_first_activity_date DATE,
    pos_last_update_date DATE,
    
    -- Metadata
    score_version VARCHAR(20) DEFAULT 'v1.0',
    calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(wallet_address, calculated_at)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_pow_pos_wallet_address ON user_pow_pos_scores(wallet_address);
CREATE INDEX IF NOT EXISTS idx_pow_pos_calculated_at ON user_pow_pos_scores(calculated_at DESC);
CREATE INDEX IF NOT EXISTS idx_pow_pos_pow_score ON user_pow_pos_scores(pow_score DESC);
CREATE INDEX IF NOT EXISTS idx_pow_pos_pos_score ON user_pow_pos_scores(pos_score DESC);
CREATE INDEX IF NOT EXISTS idx_pow_pos_wallet_calculated ON user_pow_pos_scores(wallet_address, calculated_at DESC);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_pow_pos_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to auto-update updated_at
DROP TRIGGER IF EXISTS update_pow_pos_updated_at ON user_pow_pos_scores;
CREATE TRIGGER update_pow_pos_updated_at 
    BEFORE UPDATE ON user_pow_pos_scores
    FOR EACH ROW 
    EXECUTE FUNCTION update_pow_pos_updated_at();

-- Enable RLS
ALTER TABLE user_pow_pos_scores ENABLE ROW LEVEL SECURITY;

-- RLS Policy: Service role can manage scores
DROP POLICY IF EXISTS "Service role can manage pow_pos_scores" ON user_pow_pos_scores;
CREATE POLICY "Service role can manage pow_pos_scores" ON user_pow_pos_scores 
    FOR ALL USING (true) WITH CHECK (true);

-- View: Latest scores per wallet
CREATE OR REPLACE VIEW latest_pow_pos_scores AS
SELECT DISTINCT ON (wallet_address) 
    score_id,
    wallet_id,
    wallet_address,
    pow_score,
    pow_tickets_purchased,
    pow_events_attended,
    pow_marketplace_txns,
    pow_referrals,
    pos_score,
    pos_nft_tickets_held,
    pos_wallet_balance_eth,
    pos_days_active,
    calculated_at,
    updated_at
FROM user_pow_pos_scores
ORDER BY wallet_address, calculated_at DESC;
