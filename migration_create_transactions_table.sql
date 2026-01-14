-- ============================================================================
-- MIGRATION: Create Transactions Table for ML Feature Engineering
-- ============================================================================
-- Purpose: Create transactions table that ML feature engineering expects
-- Run this in Supabase SQL Editor
-- ============================================================================

-- Create transactions table for ML feature engineering
CREATE TABLE IF NOT EXISTS transactions (
    transaction_id VARCHAR(255) PRIMARY KEY,
    wallet_address VARCHAR(255) NOT NULL,
    event_id BIGINT REFERENCES events(event_id) ON DELETE SET NULL,
    ticket_id BIGINT REFERENCES tickets(ticket_id) ON DELETE SET NULL,
    order_id BIGINT REFERENCES orders(order_id) ON DELETE SET NULL,
    price_paid NUMERIC(18, 8) NOT NULL,
    payment_method VARCHAR(50),
    transaction_type VARCHAR(50) CHECK (transaction_type IN ('PURCHASE', 'RESALE', 'TRANSFER')),
    ip_address VARCHAR(45),
    user_agent TEXT,
    status VARCHAR(50) CHECK (status IN ('PENDING', 'COMPLETED', 'FAILED')),
    blockchain_hash VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

-- Indexes for ML queries
CREATE INDEX IF NOT EXISTS idx_transactions_wallet_address ON transactions(wallet_address);
CREATE INDEX IF NOT EXISTS idx_transactions_created_at ON transactions(created_at);
CREATE INDEX IF NOT EXISTS idx_transactions_event_id ON transactions(event_id);
CREATE INDEX IF NOT EXISTS idx_transactions_wallet_created ON transactions(wallet_address, created_at);
CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status);

-- Function: Create transaction record from order
CREATE OR REPLACE FUNCTION create_transaction_from_order()
RETURNS TRIGGER AS $$
DECLARE
    wallet_addr VARCHAR(255);
BEGIN
    -- Get wallet address from wallet_id
    SELECT address INTO wallet_addr
    FROM wallets
    WHERE wallet_id = NEW.buyer_wallet_id;
    
    IF wallet_addr IS NULL THEN
        RETURN NEW;
    END IF;
    
    -- Insert transaction record
    INSERT INTO transactions (
        transaction_id,
        wallet_address,
        event_id,
        ticket_id,
        order_id,
        price_paid,
        transaction_type,
        status,
        created_at,
        completed_at
    )
    VALUES (
        'txn_' || NEW.order_id::text,
        wallet_addr,
        NEW.event_id,
        NEW.ticket_id,
        NEW.order_id,
        NEW.price,
        COALESCE(NEW.order_type, 'PRIMARY'),
        NEW.status,
        NEW.created_at,
        NEW.completed_at
    )
    ON CONFLICT (transaction_id) DO NOTHING;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger: Auto-create transaction record on order creation
DROP TRIGGER IF EXISTS trigger_create_transaction_on_order ON orders;
CREATE TRIGGER trigger_create_transaction_on_order
    AFTER INSERT ON orders
    FOR EACH ROW
    EXECUTE FUNCTION create_transaction_from_order();

-- Trigger: Update transaction status when order status changes
CREATE OR REPLACE FUNCTION update_transaction_from_order()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE transactions
    SET status = NEW.status,
        completed_at = NEW.completed_at
    WHERE order_id = NEW.order_id;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_update_transaction_on_order ON orders;
CREATE TRIGGER trigger_update_transaction_on_order
    AFTER UPDATE ON orders
    FOR EACH ROW
    WHEN (OLD.status IS DISTINCT FROM NEW.status)
    EXECUTE FUNCTION update_transaction_from_order();

-- Also create transactions from resales table
CREATE OR REPLACE FUNCTION create_transaction_from_resale()
RETURNS TRIGGER AS $$
DECLARE
    wallet_addr VARCHAR(255);
    event_id_val BIGINT;
BEGIN
    -- Get seller wallet address
    SELECT address INTO wallet_addr
    FROM wallets
    WHERE wallet_id = NEW.seller_wallet_id;
    
    -- Get event_id from ticket
    SELECT event_id INTO event_id_val
    FROM tickets
    WHERE ticket_id = NEW.ticket_id;
    
    IF wallet_addr IS NULL THEN
        RETURN NEW;
    END IF;
    
    -- Insert transaction record for resale listing
    INSERT INTO transactions (
        transaction_id,
        wallet_address,
        event_id,
        ticket_id,
        price_paid,
        transaction_type,
        status,
        created_at
    )
    VALUES (
        'resale_' || NEW.resale_id::text,
        wallet_addr,
        event_id_val,
        NEW.ticket_id,
        NEW.listing_price,
        'RESALE',
        CASE WHEN NEW.status = 'SOLD' THEN 'COMPLETED' ELSE 'PENDING' END,
        NEW.listed_at
    )
    ON CONFLICT (transaction_id) DO NOTHING;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_create_transaction_on_resale ON resales;
CREATE TRIGGER trigger_create_transaction_on_resale
    AFTER INSERT ON resales
    FOR EACH ROW
    EXECUTE FUNCTION create_transaction_from_resale();

-- Enable RLS on transactions table
ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;

-- RLS Policy: Service role can manage transactions
DROP POLICY IF EXISTS "Service role can manage transactions" ON transactions;
CREATE POLICY "Service role can manage transactions" ON transactions 
    FOR ALL USING (true) WITH CHECK (true);
