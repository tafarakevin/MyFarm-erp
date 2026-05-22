# Thornfield ERP — Integrated Farm Operations & Financial Intelligence Platform

A real-time agricultural ERP platform built on Flask + PostgreSQL, extending the Thornfield Estate Management System into a full operational intelligence suite.

---

## What This Is

This is a **production-ready ERP extension** of the original Thornfield farm management system. Every farm activity now automatically impacts inventory, operational costs, budgeting, profitability, forecasting, and executive analytics — all in one place.

---

## Default Login

| Field    | Value                      |
|----------|----------------------------|
| Email    | `admin@thornfield.com`     |
| Password | `thornfield2025`           |

---

## Deployment (Railway)

1. Push this repo to GitHub
2. Create a new Railway project → **Deploy from GitHub**
3. Add a **PostgreSQL** plugin — Railway auto-sets `DATABASE_URL`
4. Set environment variable: `PORT=8080` (Railway sets this automatically)
5. Deploy — the app initialises all tables and seeds demo data on first boot

```
railway up
```

The `railway.json` and `nixpacks.toml` are pre-configured.

---

## Architecture

```
thornfield-erp/
├── server.py           # Flask backend — original + ERP extension (2800+ lines)
├── public/
│   └── Index.html      # Single-page app — original UI + ERP module (7700+ lines)
├── erp_schema.sql      # Reference schema (applied automatically at startup)
├── requirements.txt    # flask, gunicorn, psycopg2-binary
├── railway.json        # Railway deployment config
├── nixpacks.toml       # Build config
└── runtime.txt         # Python version
```

### Backend: `server.py`
- **Original modules preserved**: auth, assets, livestock, crops, workers, inventory, finance, compliance, reports, settings, audit log
- **ERP extension appended** (never modifies original logic):
  - `init_erp_db()` — creates 15 new ERP tables
  - `seed_erp_db()` — seeds Thornfield demo data into ERP tables
  - 31 new `/api/erp/*` routes covering every ERP domain

### Frontend: `public/Index.html`
- Original SPA UI untouched
- ERP CSS + JS module appended (1000+ lines)
- 9 new ERP navigation pages added to the sidebar under "ERP Intelligence"
- `loadPage()` router extended for all ERP pages

---

## ERP Modules

### 1. Executive KPI Dashboard (`/erp-dashboard`)
- Live profitability waterfall (revenue → expenses → original profit → contingency → adjusted profit)
- Revenue vs projection percentage
- Budget utilization tracking
- 6-month revenue/expense trend chart
- Recent operations log
- Operational alerts (low stock, compliance, budget overruns)

### 2. Profitability Analysis (`/erp-profitability`)
- Full P&L statement by category
- **Contingency Engine**: set % or fixed contingency, shows original profit, contingency value, adjusted expenses, and adjusted profit separately — never hides original figures
- Revenue projections (manual entry, projected vs actual comparison)
- Formula: `Adjusted Profit = Revenue − (Expenses + Contingency)`

### 3. Budgets & Forecasts (`/erp-budgets`)
- Per-season budget lines by category
- Budget variance analysis: planned vs actual, under/over status, progress bars
- 18-month cash flow table with cumulative position

### 4. Operational Log (`/erp-activities`)
- Log any farm activity: fertilizer application, feeding, fuel usage, planting, harvesting, spraying, vaccination, irrigation, etc.
- **Real-time inventory deduction**: selecting inventory items auto-deducts stock using LIFO lot costing
- Auto-generates finance expense entry for every activity with cost
- Low-stock notifications triggered automatically when items fall below par level
- Full activity history with cost, unit, and performer

### 5. Cost Analytics (`/erp-costing`)
- Per-operational-unit cost & profitability (cost, revenue, profit, cost/ha)
- Labour cost analysis: hours logged, allocated cost, salary
- Inventory valuation: current stock value, consumed value, below-par alerts

### 6. Production Records (`/erp-production`)
- Log harvest batches, milk production, sales
- Yield analysis per unit (yield/ha)
- Auto-creates income finance entry when actual revenue is entered

### 7. Asset Depreciation (`/erp-depreciation`)
- Straight-line and declining-balance depreciation schedules
- Run depreciation periods (records expense automatically)
- Book value tracking (asset value − accumulated depreciation)

### 8. Operational Units (`/erp-units`)
- Define fields, herds, greenhouses, warehouses, pens, silos, orchards, paddocks
- Multi-farm support
- All activities and production link to units for per-unit analytics

### 9. Season Management (`/erp-seasons`)
- Create and manage production seasons (Planning → Active → Closed)
- Budgets and revenue projections scoped per season
- Season-level profitability analysis

---

## Database Schema — New ERP Tables

| Table | Purpose |
|---|---|
| `farms` | Multi-farm support |
| `operational_units` | Fields, herds, warehouses, etc. |
| `seasons` | Production seasons |
| `budgets` | Planned expenditure per category |
| `revenue_projections` | Manual revenue targets (projected vs actual) |
| `contingency_settings` | % or fixed contingency per season |
| `cost_centers` | Named cost buckets |
| `inventory_lots` | LIFO lot-based inventory tracking |
| `operational_activities` | Core ERP event: every farm action |
| `inventory_consumption` | Links activities → inventory deductions |
| `labor_allocations` | Worker hours & cost linked to activities |
| `production_batches` | Harvest and production records |
| `asset_depreciation` | Depreciation schedules and accumulated values |
| `kpi_snapshots` | Historical KPI snapshots |
| `notifications` | In-app alerts (low stock, budget warnings) |

---

## Core Business Rules

### Inventory (LIFO)
- Receiving inventory → creates lot, increases `on_hand`, records expense in `finance`
- Using inventory in an activity → deducts LIFO lots, records consumption cost, decreases `on_hand`, auto-creates finance expense
- Low-stock alert fires when `on_hand ≤ par_level`

### Profitability Formula
```
Original Profit     = Revenue − Expenses
Contingency Value   = Expenses × contingency_pct%  OR  fixed_amount
Adjusted Expenses   = Expenses + Contingency Value
Adjusted Profit     = Revenue − Adjusted Expenses
```

### Activity → Finance Sync
Every completed operational activity with `total_cost > 0` automatically creates a matching `finance` expense record tagged with `ACT-{id}` reference.

### Production → Finance Sync
Every production batch with `actual_revenue > 0` automatically creates a `finance` income record tagged with `PROD-{id}` reference.

---

## Role Access

| Role | ERP Access |
|---|---|
| `owner` | Full access to all 9 ERP modules |
| `manager` | Full access to all 9 ERP modules |
| `finance` | Dashboard, Profitability, Budgets, Cost Analytics |
| `field` | No ERP access |

---

## API Reference (ERP Routes)

| Method | Route | Description |
|---|---|---|
| GET | `/api/erp/dashboard` | Full executive KPI payload |
| GET | `/api/erp/profitability` | Profitability engine output |
| GET/POST | `/api/erp/farms` | Farm management |
| GET/POST | `/api/erp/units` | Operational units |
| GET/POST | `/api/erp/seasons` | Season management |
| GET/POST | `/api/erp/budgets` | Budget lines |
| GET/POST | `/api/erp/revenue-projections` | Revenue projections |
| GET/POST | `/api/erp/contingency` | Contingency settings |
| GET/POST | `/api/erp/activities` | Operational activities (with inventory deduction) |
| GET/POST | `/api/erp/labor` | Labour allocations |
| GET/POST | `/api/erp/production` | Production batches |
| GET/POST | `/api/erp/inventory-lots` | Inventory lot receipts |
| GET/POST | `/api/erp/depreciation` | Depreciation schedules |
| POST | `/api/erp/depreciation/{id}/run` | Run depreciation period |
| GET | `/api/erp/analytics/pl-summary` | P&L by category |
| GET | `/api/erp/analytics/budget-variance` | Planned vs actual |
| GET | `/api/erp/analytics/cash-flow` | 18-month cash flow |
| GET | `/api/erp/analytics/unit-costs` | Per-unit cost/profit |
| GET | `/api/erp/analytics/labor-costs` | Labour analysis |
| GET | `/api/erp/analytics/inventory-valuation` | Stock value report |
| GET | `/api/erp/analytics/yield-analysis` | Yield per unit/ha |
| GET/POST | `/api/erp/notifications` | In-app notifications |

---

## Extension Points

The architecture is designed to be extended:

- **AI modules**: plug into `/api/erp/analytics/*` endpoints for yield prediction, anomaly detection, procurement recommendations
- **WhatsApp alerts**: add Twilio/WhatsApp calls inside `create_notification()` 
- **WebSockets**: wrap activity creation and inventory changes with `flask-socketio` for real-time dashboard updates
- **React migration**: all data is available via clean REST API — swap `Index.html` for a React/Vite frontend without touching `server.py`
- **Additional farm types**: add new `unit_type` values (aquaculture, apiary, nursery) — the activity system handles them automatically

---

## Tech Stack

- **Backend**: Python 3.11, Flask 3, Gunicorn, psycopg2
- **Database**: PostgreSQL (managed by Railway)
- **Frontend**: Vanilla JS SPA, Material Symbols, DM Sans + Cormorant Garamond, custom dark design system
- **Deployment**: Railway (nixpacks, auto-deploy from GitHub)
