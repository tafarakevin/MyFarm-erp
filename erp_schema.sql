-- ═══════════════════════════════════════════════════════════════════════════════
-- THORNFIELD ERP — EXTENDED SCHEMA (Migration / Reference)
-- ═══════════════════════════════════════════════════════════════════════════════

-- FARMS (multi-farm support)
CREATE TABLE IF NOT EXISTS farms (
    id          SERIAL PRIMARY KEY,
    name        TEXT    NOT NULL,
    location    TEXT,
    total_ha    NUMERIC DEFAULT 0,
    currency    TEXT    DEFAULT 'USD',
    notes       TEXT,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- OPERATIONAL UNITS (fields, herds, greenhouses, etc.)
CREATE TABLE IF NOT EXISTS operational_units (
    id          SERIAL PRIMARY KEY,
    farm_id     INTEGER REFERENCES farms(id) ON DELETE CASCADE,
    name        TEXT    NOT NULL,
    unit_type   TEXT    NOT NULL CHECK(unit_type IN ('field','herd','greenhouse','warehouse','pen','silo','orchard','paddock','other')),
    area_ha     NUMERIC DEFAULT 0,
    notes       TEXT,
    active      BOOLEAN DEFAULT TRUE,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- SEASONS
CREATE TABLE IF NOT EXISTS seasons (
    id          SERIAL PRIMARY KEY,
    farm_id     INTEGER REFERENCES farms(id) ON DELETE CASCADE,
    name        TEXT    NOT NULL,
    start_date  DATE    NOT NULL,
    end_date    DATE,
    status      TEXT    DEFAULT 'Active' CHECK(status IN ('Planning','Active','Closed')),
    notes       TEXT,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- BUDGETS
CREATE TABLE IF NOT EXISTS budgets (
    id              SERIAL PRIMARY KEY,
    season_id       INTEGER REFERENCES seasons(id) ON DELETE CASCADE,
    unit_id         INTEGER REFERENCES operational_units(id) ON DELETE SET NULL,
    category        TEXT    NOT NULL,
    planned_amount  NUMERIC NOT NULL DEFAULT 0,
    notes           TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- REVENUE PROJECTIONS (manual entry)
CREATE TABLE IF NOT EXISTS revenue_projections (
    id              SERIAL PRIMARY KEY,
    season_id       INTEGER REFERENCES seasons(id) ON DELETE CASCADE,
    unit_id         INTEGER REFERENCES operational_units(id) ON DELETE SET NULL,
    description     TEXT    NOT NULL,
    projected_amount NUMERIC NOT NULL DEFAULT 0,
    actual_amount   NUMERIC DEFAULT 0,
    notes           TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- CONTINGENCY SETTINGS
CREATE TABLE IF NOT EXISTS contingency_settings (
    id              SERIAL PRIMARY KEY,
    season_id       INTEGER REFERENCES seasons(id) ON DELETE CASCADE,
    contingency_type TEXT   DEFAULT 'percentage' CHECK(contingency_type IN ('percentage','fixed')),
    contingency_pct  NUMERIC DEFAULT 0,
    contingency_fixed NUMERIC DEFAULT 0,
    notes           TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- COST CENTERS
CREATE TABLE IF NOT EXISTS cost_centers (
    id          SERIAL PRIMARY KEY,
    farm_id     INTEGER REFERENCES farms(id) ON DELETE CASCADE,
    name        TEXT    NOT NULL,
    code        TEXT,
    description TEXT,
    active      BOOLEAN DEFAULT TRUE,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- INVENTORY LOTS (lot-based tracking for LIFO/valuation)
CREATE TABLE IF NOT EXISTS inventory_lots (
    id              SERIAL PRIMARY KEY,
    inventory_id    INTEGER NOT NULL REFERENCES inventory(id) ON DELETE CASCADE,
    lot_number      TEXT,
    quantity_received NUMERIC NOT NULL DEFAULT 0,
    quantity_remaining NUMERIC NOT NULL DEFAULT 0,
    unit_cost       NUMERIC NOT NULL DEFAULT 0,
    total_cost      NUMERIC GENERATED ALWAYS AS (quantity_received * unit_cost) STORED,
    received_date   DATE    DEFAULT CURRENT_DATE,
    expiry_date     DATE,
    supplier        TEXT,
    notes           TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- OPERATIONAL ACTIVITIES (the core ERP event bus)
CREATE TABLE IF NOT EXISTS operational_activities (
    id              SERIAL PRIMARY KEY,
    activity_type   TEXT    NOT NULL,  -- fertilizer_application, feeding, fuel_usage, planting, harvesting, spraying, vaccination, etc.
    unit_id         INTEGER REFERENCES operational_units(id) ON DELETE SET NULL,
    season_id       INTEGER REFERENCES seasons(id) ON DELETE SET NULL,
    cost_center_id  INTEGER REFERENCES cost_centers(id) ON DELETE SET NULL,
    description     TEXT    NOT NULL,
    activity_date   DATE    DEFAULT CURRENT_DATE,
    status          TEXT    DEFAULT 'Completed' CHECK(status IN ('Planned','In Progress','Completed','Cancelled')),
    total_cost      NUMERIC DEFAULT 0,
    notes           TEXT,
    performed_by    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- INVENTORY CONSUMPTION (links activities → inventory deductions)
CREATE TABLE IF NOT EXISTS inventory_consumption (
    id              SERIAL PRIMARY KEY,
    activity_id     INTEGER NOT NULL REFERENCES operational_activities(id) ON DELETE CASCADE,
    inventory_id    INTEGER NOT NULL REFERENCES inventory(id) ON DELETE RESTRICT,
    lot_id          INTEGER REFERENCES inventory_lots(id) ON DELETE SET NULL,
    quantity_used   NUMERIC NOT NULL DEFAULT 0,
    unit_cost       NUMERIC NOT NULL DEFAULT 0,
    total_cost      NUMERIC GENERATED ALWAYS AS (quantity_used * unit_cost) STORED,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- LABOR ALLOCATIONS
CREATE TABLE IF NOT EXISTS labor_allocations (
    id              SERIAL PRIMARY KEY,
    activity_id     INTEGER REFERENCES operational_activities(id) ON DELETE CASCADE,
    worker_id       INTEGER REFERENCES workers(id) ON DELETE SET NULL,
    unit_id         INTEGER REFERENCES operational_units(id) ON DELETE SET NULL,
    hours           NUMERIC DEFAULT 0,
    hourly_rate     NUMERIC DEFAULT 0,
    total_cost      NUMERIC GENERATED ALWAYS AS (hours * hourly_rate) STORED,
    allocation_date DATE    DEFAULT CURRENT_DATE,
    notes           TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- PRODUCTION BATCHES (harvest records, milk, etc.)
CREATE TABLE IF NOT EXISTS production_batches (
    id              SERIAL PRIMARY KEY,
    unit_id         INTEGER REFERENCES operational_units(id) ON DELETE SET NULL,
    season_id       INTEGER REFERENCES seasons(id) ON DELETE SET NULL,
    product_type    TEXT    NOT NULL,  -- maize, milk, beef, tobacco, etc.
    quantity        NUMERIC NOT NULL DEFAULT 0,
    unit_of_measure TEXT    NOT NULL DEFAULT 'kg',
    actual_revenue  NUMERIC DEFAULT 0,
    batch_date      DATE    DEFAULT CURRENT_DATE,
    notes           TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ASSET DEPRECIATION
CREATE TABLE IF NOT EXISTS asset_depreciation (
    id              SERIAL PRIMARY KEY,
    asset_id        INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    method          TEXT    DEFAULT 'straight_line' CHECK(method IN ('straight_line','declining_balance')),
    useful_life_years NUMERIC DEFAULT 5,
    residual_value  NUMERIC DEFAULT 0,
    depreciation_start DATE DEFAULT CURRENT_DATE,
    annual_depreciation NUMERIC DEFAULT 0,
    accumulated_depreciation NUMERIC DEFAULT 0,
    notes           TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- KPI SNAPSHOTS (for dashboard caching / time-series)
CREATE TABLE IF NOT EXISTS kpi_snapshots (
    id              SERIAL PRIMARY KEY,
    snapshot_date   DATE    DEFAULT CURRENT_DATE,
    total_revenue   NUMERIC DEFAULT 0,
    total_expenses  NUMERIC DEFAULT 0,
    net_profit      NUMERIC DEFAULT 0,
    inventory_value NUMERIC DEFAULT 0,
    labor_cost      NUMERIC DEFAULT 0,
    livestock_count INTEGER DEFAULT 0,
    crop_ha         NUMERIC DEFAULT 0,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- NOTIFICATIONS
CREATE TABLE IF NOT EXISTS notifications (
    id              SERIAL PRIMARY KEY,
    user_id         INTEGER REFERENCES users(id) ON DELETE CASCADE,
    title           TEXT    NOT NULL,
    message         TEXT    NOT NULL,
    notification_type TEXT  DEFAULT 'info' CHECK(notification_type IN ('info','warning','alert','success')),
    related_type    TEXT,
    related_id      INTEGER,
    read_at         TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- INDEXES for performance
CREATE INDEX IF NOT EXISTS idx_operational_activities_unit ON operational_activities(unit_id);
CREATE INDEX IF NOT EXISTS idx_operational_activities_date ON operational_activities(activity_date);
CREATE INDEX IF NOT EXISTS idx_inventory_consumption_activity ON inventory_consumption(activity_id);
CREATE INDEX IF NOT EXISTS idx_inventory_consumption_inventory ON inventory_consumption(inventory_id);
CREATE INDEX IF NOT EXISTS idx_labor_allocations_worker ON labor_allocations(worker_id);
CREATE INDEX IF NOT EXISTS idx_production_batches_unit ON production_batches(unit_id);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);
CREATE INDEX IF NOT EXISTS idx_finance_date ON finance(date);
CREATE INDEX IF NOT EXISTS idx_finance_type ON finance(type);
