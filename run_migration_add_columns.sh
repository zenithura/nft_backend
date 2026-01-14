#!/bin/bash
# Script to add missing columns to events table
# Run this if you get errors about missing 'category', 'image_url', or 'currency' columns

echo "Running migration to add image_url, category, and currency columns to events table..."
echo ""
echo "Please run the following SQL in your Supabase SQL Editor:"
echo ""
echo "ALTER TABLE events ADD COLUMN IF NOT EXISTS image_url TEXT;"
echo "ALTER TABLE events ADD COLUMN IF NOT EXISTS category VARCHAR(100) DEFAULT 'All';"
echo "ALTER TABLE events ADD COLUMN IF NOT EXISTS currency VARCHAR(10) DEFAULT 'ETH';"
echo ""
echo "Or run: backend/migration_add_columns.sql"
echo ""
