"""
Thornfield Estate — Enterprise ERP Engine
==========================================
Phases 1–10: Calculation Engine, Cost Accounting, COGS, Advanced Profitability,
Forecasting & Scenario Modelling, Inventory Optimisation, Livestock Analytics,
Crop Analytics, Labour Analytics, Asset Performance Management.

Architecture
------------
This module is imported once by server.py. It registers all new Blueprint routes
and extends init_erp_db() via init_enterprise_db().

Every calculation lives exclusively in the CalculationEngine hierarchy —
no business formula is duplicated in any route handler.

Usage in server.py (add at the bottom, before _on_startup()):
    from erp_engine import register_enterprise_routes, init_enterprise_db
    register_enterprise_routes(app)
    # call init_enterprise_db() inside your _on_startup / init chain
"""

from __future__ import annotations

import json
import os
from datetime import datetime, date, timedelta
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Dict, List, Optional, Tuple

import psycopg2
import psycopg2.extras
from flask import Blueprint, Flask, g, jsonify, request

# ── Re-use server.py helpers (imported at runtime so no circular import) ────────
# server.py must set these in its module scope before calling register_enterprise_routes()
_server = None  # populated by register_enterprise_routes()


def _q(sql, args=(), one=False):
    return _server.query(sql, args, one)


def _m(sql, args=()):
    return _server.mutate(sql, args)


def _tx():
    return _server.db_transaction()


def _tx_m(cur, sql, args=()):
    return _server.tx_mutate(cur, sql, args)


def _tx_q(cur, sql, args=(), one=False):
    return _server.tx_query(cur, sql, args, one)


def _audit(cur, *a, **kw):
    return _server.write_audit(cur, *a, **kw)


def _rows(rows):
    return [dict(r) for r in rows]


def _row(row):
    return dict(row) if row else None


def _float(v, default=0.0) -> float:
    try:
        return float(v) if v is not None else default
    except (TypeError, ValueError):
        return default


def _safe_div(numerator: float, denominator: float, default=0.0) -> float:
    return round(numerator / denominator, 4) if denominator else default


def _pct(part: float, whole: float) -> float:
    return round(part / whole * 100, 2) if whole else 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1 — CENTRAL CALCULATION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class CalculationMeta:
    """Registry entry for a named formula."""
    __slots__ = ("name", "version", "description", "module", "formula_fn")

    def __init__(self, name: str, version: str, description: str, module: str, formula_fn):
        self.name = name
        self.version = version
        self.description = description
        self.module = module
        self.formula_fn = formula_fn

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "module": self.module,
        }


class _CalculationRegistry:
    """Central registry — all formulas register here; no duplicates allowed."""
    _registry: Dict[str, CalculationMeta] = {}

    @classmethod
    def register(cls, name: str, version: str, description: str, module: str):
        """Decorator: @CalculationRegistry.register(...)"""
        def decorator(fn):
            if name in cls._registry:
                raise ValueError(f"Formula '{name}' already registered by {cls._registry[name].module}")
            cls._registry[name] = CalculationMeta(name, version, description, module, fn)
            return fn
        return decorator

    @classmethod
    def get(cls, name: str) -> Optional[CalculationMeta]:
        return cls._registry.get(name)

    @classmethod
    def all_formulas(cls) -> List[dict]:
        return [m.to_dict() for m in cls._registry.values()]

    @classmethod
    def invoke(cls, name: str, *args, **kwargs):
        meta = cls.get(name)
        if not meta:
            raise KeyError(f"Formula '{name}' not found in registry")
        return meta.formula_fn(*args, **kwargs)


CalculationRegistry = _CalculationRegistry()


def _log_calculation_audit(formula_name: str, inputs: dict, result: Any, user_id=None):
    """Write a formula execution record to calc_audit_log (best-effort, non-blocking)."""
    try:
        _m(
            """INSERT INTO calc_audit_log
               (formula_name, inputs, result, performed_by, created_at)
               VALUES (%s, %s, %s, %s, NOW())""",
            (formula_name, json.dumps(inputs, default=str), json.dumps(result, default=str), user_id)
        )
    except Exception:
        pass


# ── FinanceCalculator ────────────────────────────────────────────────────────

class FinanceCalculator:

    @staticmethod
    @CalculationRegistry.register("gross_profit", "1.0", "Revenue minus COGS", "FinanceCalculator")
    def gross_profit(revenue: float, cogs: float) -> float:
        return round(revenue - cogs, 2)

    @staticmethod
    @CalculationRegistry.register("operating_profit", "1.0", "Gross profit minus operating expenses", "FinanceCalculator")
    def operating_profit(gross_profit: float, operating_expenses: float) -> float:
        return round(gross_profit - operating_expenses, 2)

    @staticmethod
    @CalculationRegistry.register("ebitda", "1.0", "Operating profit + D&A", "FinanceCalculator")
    def ebitda(operating_profit: float, depreciation: float, amortisation: float = 0.0) -> float:
        return round(operating_profit + depreciation + amortisation, 2)

    @staticmethod
    @CalculationRegistry.register("net_profit", "1.0", "Profit after tax and interest", "FinanceCalculator")
    def net_profit(ebitda: float, interest: float, tax: float) -> float:
        return round(ebitda - interest - tax, 2)

    @staticmethod
    @CalculationRegistry.register("gross_margin_pct", "1.0", "Gross profit as % of revenue", "FinanceCalculator")
    def gross_margin_pct(revenue: float, cogs: float) -> float:
        gp = revenue - cogs
        return _pct(gp, revenue)

    @staticmethod
    @CalculationRegistry.register("adjusted_profit", "1.0", "Profit after contingency provision", "FinanceCalculator")
    def adjusted_profit(profit: float, contingency: float) -> float:
        return round(profit - contingency, 2)

    @staticmethod
    @CalculationRegistry.register("roi", "1.0", "Return on investment percentage", "FinanceCalculator")
    def roi(net_profit: float, total_investment: float) -> float:
        return _pct(net_profit, total_investment)

    @staticmethod
    @CalculationRegistry.register("payback_period_years", "1.0", "Investment payback in years", "FinanceCalculator")
    def payback_period_years(total_investment: float, annual_net_cashflow: float) -> float:
        return _safe_div(total_investment, annual_net_cashflow)


# ── CropCalculator ───────────────────────────────────────────────────────────

class CropCalculator:

    @staticmethod
    @CalculationRegistry.register("yield_per_ha", "1.0", "Total yield divided by area", "CropCalculator")
    def yield_per_ha(total_yield_kg: float, area_ha: float) -> float:
        return round(_safe_div(total_yield_kg, area_ha), 2)

    @staticmethod
    @CalculationRegistry.register("revenue_per_ha", "1.0", "Revenue divided by area", "CropCalculator")
    def revenue_per_ha(revenue: float, area_ha: float) -> float:
        return round(_safe_div(revenue, area_ha), 2)

    @staticmethod
    @CalculationRegistry.register("cost_per_ha", "1.0", "Total cost divided by area", "CropCalculator")
    def cost_per_ha(total_cost: float, area_ha: float) -> float:
        return round(_safe_div(total_cost, area_ha), 2)

    @staticmethod
    @CalculationRegistry.register("profit_per_ha", "1.0", "Net profit divided by area", "CropCalculator")
    def profit_per_ha(profit: float, area_ha: float) -> float:
        return round(_safe_div(profit, area_ha), 2)

    @staticmethod
    @CalculationRegistry.register("yield_variance_pct", "1.0", "Variance of actual vs estimated yield", "CropCalculator")
    def yield_variance_pct(actual_yield: float, estimated_yield: float) -> float:
        if not estimated_yield:
            return 0.0
        return round((actual_yield - estimated_yield) / estimated_yield * 100, 2)

    @staticmethod
    @CalculationRegistry.register("crop_gross_margin", "1.0", "Revenue minus variable costs for a crop", "CropCalculator")
    def crop_gross_margin(revenue: float, variable_costs: float) -> float:
        return round(revenue - variable_costs, 2)

    @staticmethod
    @CalculationRegistry.register("water_use_efficiency", "1.0", "Yield per mm of water applied", "CropCalculator")
    def water_use_efficiency(yield_kg: float, water_mm: float) -> float:
        return round(_safe_div(yield_kg, water_mm), 4)

    @staticmethod
    @CalculationRegistry.register("input_cost_per_ha", "1.0", "Input costs per hectare", "CropCalculator")
    def input_cost_per_ha(seed: float, fertiliser: float, chemicals: float, other: float, area_ha: float) -> float:
        total = seed + fertiliser + chemicals + other
        return round(_safe_div(total, area_ha), 2)


# ── LivestockCalculator ──────────────────────────────────────────────────────

class LivestockCalculator:

    @staticmethod
    @CalculationRegistry.register("feed_cost_per_head", "1.0", "Total feed cost divided by herd count", "LivestockCalculator")
    def feed_cost_per_head(total_feed_cost: float, head_count: int) -> float:
        return round(_safe_div(total_feed_cost, head_count), 2)

    @staticmethod
    @CalculationRegistry.register("vet_cost_per_head", "1.0", "Vet costs per animal", "LivestockCalculator")
    def vet_cost_per_head(total_vet_cost: float, head_count: int) -> float:
        return round(_safe_div(total_vet_cost, head_count), 2)

    @staticmethod
    @CalculationRegistry.register("revenue_per_head", "1.0", "Livestock revenue per animal", "LivestockCalculator")
    def revenue_per_head(total_revenue: float, head_count: int) -> float:
        return round(_safe_div(total_revenue, head_count), 2)

    @staticmethod
    @CalculationRegistry.register("profit_per_head", "1.0", "Net profit per animal", "LivestockCalculator")
    def profit_per_head(total_profit: float, head_count: int) -> float:
        return round(_safe_div(total_profit, head_count), 2)

    @staticmethod
    @CalculationRegistry.register("mortality_rate", "1.0", "Deaths as percentage of opening stock", "LivestockCalculator")
    def mortality_rate(deaths: int, opening_count: int) -> float:
        return _pct(deaths, opening_count)

    @staticmethod
    @CalculationRegistry.register("birth_rate", "1.0", "Births as percentage of breeding females", "LivestockCalculator")
    def birth_rate(births: int, breeding_females: int) -> float:
        return _pct(births, breeding_females)

    @staticmethod
    @CalculationRegistry.register("feed_conversion_ratio", "1.0", "Feed consumed per kg weight gain", "LivestockCalculator")
    def feed_conversion_ratio(feed_consumed_kg: float, weight_gain_kg: float) -> float:
        return round(_safe_div(feed_consumed_kg, weight_gain_kg), 2)

    @staticmethod
    @CalculationRegistry.register("average_daily_gain", "1.0", "Average weight gained per animal per day", "LivestockCalculator")
    def average_daily_gain(total_weight_gain_kg: float, days: int, head_count: int) -> float:
        total_head_days = days * head_count
        return round(_safe_div(total_weight_gain_kg, total_head_days), 4)

    @staticmethod
    @CalculationRegistry.register("stocking_rate", "1.0", "Animals per hectare", "LivestockCalculator")
    def stocking_rate(head_count: int, area_ha: float) -> float:
        return round(_safe_div(head_count, area_ha), 2)

    @staticmethod
    @CalculationRegistry.register("total_livestock_cogs", "1.0", "Full COGS for a livestock enterprise", "LivestockCalculator")
    def total_livestock_cogs(feed: float, vet: float, breeding: float,
                              labour: float, medicines: float, transport: float) -> float:
        return round(feed + vet + breeding + labour + medicines + transport, 2)


# ── InventoryCalculator ──────────────────────────────────────────────────────

class InventoryCalculator:

    @staticmethod
    @CalculationRegistry.register("inventory_turnover", "1.0", "COGS / Average inventory value", "InventoryCalculator")
    def inventory_turnover(cogs: float, avg_inventory_value: float) -> float:
        return round(_safe_div(cogs, avg_inventory_value), 2)

    @staticmethod
    @CalculationRegistry.register("days_inventory_remaining", "1.0", "Days of stock at current consumption", "InventoryCalculator")
    def days_inventory_remaining(on_hand: float, daily_consumption: float) -> float:
        return round(_safe_div(on_hand, daily_consumption), 1)

    @staticmethod
    @CalculationRegistry.register("economic_order_quantity", "1.0", "Wilson EOQ formula", "InventoryCalculator")
    def economic_order_quantity(annual_demand: float, order_cost: float, holding_cost_pct: float, unit_cost: float) -> float:
        """EOQ = sqrt(2DS/H) where H = holding_cost_pct * unit_cost"""
        h = holding_cost_pct * unit_cost
        if not h or not unit_cost:
            return 0.0
        import math
        return round(math.sqrt(2 * annual_demand * order_cost / h), 2)

    @staticmethod
    @CalculationRegistry.register("reorder_point", "1.0", "Average daily demand * lead time + safety stock", "InventoryCalculator")
    def reorder_point(daily_demand: float, lead_time_days: float, safety_stock: float) -> float:
        return round(daily_demand * lead_time_days + safety_stock, 2)

    @staticmethod
    @CalculationRegistry.register("safety_stock", "1.0", "z-score * stddev of daily demand * sqrt(lead time)", "InventoryCalculator")
    def safety_stock(z_score: float, demand_stddev: float, lead_time_days: float) -> float:
        import math
        return round(z_score * demand_stddev * math.sqrt(lead_time_days), 2)

    @staticmethod
    @CalculationRegistry.register("avg_daily_consumption", "1.0", "Total consumed divided by period days", "InventoryCalculator")
    def avg_daily_consumption(total_consumed: float, period_days: int) -> float:
        return round(_safe_div(total_consumed, period_days), 4)

    @staticmethod
    @CalculationRegistry.register("weighted_avg_cost", "1.0", "WAVG cost across lots", "InventoryCalculator")
    def weighted_avg_cost(lots: List[Tuple[float, float]]) -> float:
        """lots = list of (quantity, unit_cost)"""
        total_qty = sum(q for q, _ in lots)
        total_val = sum(q * c for q, c in lots)
        return round(_safe_div(total_val, total_qty), 4)

    @staticmethod
    @CalculationRegistry.register("abc_classification", "1.0", "Classify item as A/B/C by cumulative value %", "InventoryCalculator")
    def abc_classification(item_value_pct_cumulative: float) -> str:
        if item_value_pct_cumulative <= 80:
            return "A"
        elif item_value_pct_cumulative <= 95:
            return "B"
        return "C"


# ── AssetCalculator ──────────────────────────────────────────────────────────

class AssetCalculator:

    @staticmethod
    @CalculationRegistry.register("straight_line_depreciation", "1.0", "Annual SLD", "AssetCalculator")
    def straight_line_depreciation(cost: float, residual: float, useful_life_years: float) -> float:
        return round(_safe_div(cost - residual, useful_life_years), 2)

    @staticmethod
    @CalculationRegistry.register("declining_balance_depreciation", "1.0", "Annual DBD at given rate", "AssetCalculator")
    def declining_balance_depreciation(book_value: float, rate_pct: float) -> float:
        return round(book_value * rate_pct / 100, 2)

    @staticmethod
    @CalculationRegistry.register("asset_book_value", "1.0", "Cost minus accumulated depreciation", "AssetCalculator")
    def asset_book_value(cost: float, accumulated_depreciation: float) -> float:
        return round(cost - accumulated_depreciation, 2)

    @staticmethod
    @CalculationRegistry.register("asset_roi", "1.0", "Net income attributable to asset / asset cost", "AssetCalculator")
    def asset_roi(net_income: float, asset_cost: float) -> float:
        return _pct(net_income, asset_cost)

    @staticmethod
    @CalculationRegistry.register("cost_per_hour", "1.0", "Asset operating cost per hour", "AssetCalculator")
    def cost_per_hour(total_operating_cost: float, total_hours: float) -> float:
        return round(_safe_div(total_operating_cost, total_hours), 2)

    @staticmethod
    @CalculationRegistry.register("asset_utilisation_pct", "1.0", "Actual hours / available hours", "AssetCalculator")
    def asset_utilisation_pct(actual_hours: float, available_hours: float) -> float:
        return _pct(actual_hours, available_hours)

    @staticmethod
    @CalculationRegistry.register("maintenance_cost_ratio", "1.0", "Maintenance cost as % of asset value", "AssetCalculator")
    def maintenance_cost_ratio(maintenance_cost: float, asset_value: float) -> float:
        return _pct(maintenance_cost, asset_value)

    @staticmethod
    @CalculationRegistry.register("asset_efficiency_score", "1.0", "Composite 0-100 asset efficiency score", "AssetCalculator")
    def asset_efficiency_score(utilisation_pct: float, roi_pct: float, maintenance_ratio_pct: float) -> float:
        # Score = 40% utilisation + 40% ROI (normalised to 100) - 20% maintenance burden
        util_score = min(utilisation_pct, 100) * 0.4
        roi_score = min(roi_pct, 100) * 0.4
        maint_penalty = min(maintenance_ratio_pct, 100) * 0.2
        return round(util_score + roi_score - maint_penalty, 1)


# ── BudgetCalculator ─────────────────────────────────────────────────────────

class BudgetCalculator:

    @staticmethod
    @CalculationRegistry.register("budget_variance", "1.0", "Planned minus actual spend", "BudgetCalculator")
    def budget_variance(planned: float, actual: float) -> float:
        return round(planned - actual, 2)

    @staticmethod
    @CalculationRegistry.register("budget_variance_pct", "1.0", "Variance as % of planned", "BudgetCalculator")
    def budget_variance_pct(planned: float, actual: float) -> float:
        variance = planned - actual
        return _pct(variance, planned)

    @staticmethod
    @CalculationRegistry.register("budget_utilisation_pct", "1.0", "Actual as % of planned budget", "BudgetCalculator")
    def budget_utilisation_pct(actual: float, planned: float) -> float:
        return _pct(actual, planned)


# ── ProfitabilityCalculator ──────────────────────────────────────────────────

class ProfitabilityCalculator:

    @staticmethod
    @CalculationRegistry.register("profit_per_worker", "1.0", "Net profit / worker count", "ProfitabilityCalculator")
    def profit_per_worker(net_profit: float, worker_count: int) -> float:
        return round(_safe_div(net_profit, worker_count), 2)

    @staticmethod
    @CalculationRegistry.register("profit_per_enterprise", "1.0", "Net profit for a cost centre", "ProfitabilityCalculator")
    def profit_per_enterprise(revenue: float, direct_costs: float, indirect_costs: float) -> float:
        return round(revenue - direct_costs - indirect_costs, 2)

    @staticmethod
    @CalculationRegistry.register("ebitda_margin", "1.0", "EBITDA as % of revenue", "ProfitabilityCalculator")
    def ebitda_margin(ebitda: float, revenue: float) -> float:
        return _pct(ebitda, revenue)

    @staticmethod
    @CalculationRegistry.register("net_margin", "1.0", "Net profit as % of revenue", "ProfitabilityCalculator")
    def net_margin(net_profit: float, revenue: float) -> float:
        return _pct(net_profit, revenue)


# ── ForecastCalculator ───────────────────────────────────────────────────────

class ForecastCalculator:

    @staticmethod
    @CalculationRegistry.register("scenario_revenue", "1.0", "Revenue under a scenario adjustment", "ForecastCalculator")
    def scenario_revenue(base_revenue: float, yield_change_pct: float, price_change_pct: float) -> float:
        yield_factor = 1 + yield_change_pct / 100
        price_factor = 1 + price_change_pct / 100
        return round(base_revenue * yield_factor * price_factor, 2)

    @staticmethod
    @CalculationRegistry.register("scenario_expenses", "1.0", "Expenses under scenario cost changes", "ForecastCalculator")
    def scenario_expenses(base_expenses: float,
                          fuel_change_pct: float = 0,
                          fertiliser_change_pct: float = 0,
                          labour_change_pct: float = 0,
                          fuel_weight: float = 0.15,
                          fertiliser_weight: float = 0.25,
                          labour_weight: float = 0.35) -> float:
        other_weight = 1 - fuel_weight - fertiliser_weight - labour_weight
        adjusted = base_expenses * (
            fuel_weight * (1 + fuel_change_pct / 100) +
            fertiliser_weight * (1 + fertiliser_change_pct / 100) +
            labour_weight * (1 + labour_change_pct / 100) +
            other_weight
        )
        return round(adjusted, 2)

    @staticmethod
    @CalculationRegistry.register("cashflow_forecast_month", "1.0", "Monthly projected cashflow", "ForecastCalculator")
    def cashflow_forecast_month(monthly_revenue: float, monthly_expenses: float, opening_balance: float) -> dict:
        net = round(monthly_revenue - monthly_expenses, 2)
        return {
            "inflows": monthly_revenue,
            "outflows": monthly_expenses,
            "net_cashflow": net,
            "closing_balance": round(opening_balance + net, 2),
        }

    @staticmethod
    @CalculationRegistry.register("trend_growth_rate", "1.0", "CAGR between two periods", "ForecastCalculator")
    def trend_growth_rate(value_start: float, value_end: float, periods: int) -> float:
        if not value_start or not periods:
            return 0.0
        return round(((value_end / value_start) ** (1 / periods) - 1) * 100, 2)


# ── TaxCalculator ────────────────────────────────────────────────────────────

class TaxCalculator:

    @staticmethod
    @CalculationRegistry.register("tax_provision", "1.0", "Simple flat-rate tax provision", "TaxCalculator")
    def tax_provision(taxable_profit: float, tax_rate_pct: float) -> float:
        if taxable_profit <= 0:
            return 0.0
        return round(taxable_profit * tax_rate_pct / 100, 2)

    @staticmethod
    @CalculationRegistry.register("vat_payable", "1.0", "Output VAT minus Input VAT", "TaxCalculator")
    def vat_payable(output_vat: float, input_vat: float) -> float:
        return round(output_vat - input_vat, 2)


# ── KPIEngine ────────────────────────────────────────────────────────────────

class KPIEngine:

    @staticmethod
    @CalculationRegistry.register("labour_productivity", "1.0", "Revenue per labour hour", "KPIEngine")
    def labour_productivity(revenue: float, total_labour_hours: float) -> float:
        return round(_safe_div(revenue, total_labour_hours), 2)

    @staticmethod
    @CalculationRegistry.register("labour_cost_per_ha", "1.0", "Total labour cost per hectare", "KPIEngine")
    def labour_cost_per_ha(labour_cost: float, area_ha: float) -> float:
        return round(_safe_div(labour_cost, area_ha), 2)

    @staticmethod
    @CalculationRegistry.register("output_per_labour_hour", "1.0", "Production output per hour worked", "KPIEngine")
    def output_per_labour_hour(total_output: float, total_hours: float) -> float:
        return round(_safe_div(total_output, total_hours), 2)

    @staticmethod
    @CalculationRegistry.register("planned_vs_actual_hours_pct", "1.0", "Labour efficiency vs plan", "KPIEngine")
    def planned_vs_actual_hours_pct(actual_hours: float, planned_hours: float) -> float:
        return _pct(actual_hours, planned_hours)

    @staticmethod
    @CalculationRegistry.register("payroll_efficiency", "1.0", "Output value / total payroll cost", "KPIEngine")
    def payroll_efficiency(output_value: float, total_payroll: float) -> float:
        return round(_safe_div(output_value, total_payroll), 2)

    @staticmethod
    @CalculationRegistry.register("cost_per_worker", "1.0", "Total people cost / worker count", "KPIEngine")
    def cost_per_worker(total_people_cost: float, worker_count: int) -> float:
        return round(_safe_div(total_people_cost, worker_count), 2)


# ═══════════════════════════════════════════════════════════════════════════════
# SCHEMA — ENTERPRISE EXTENSION TABLES
# ═══════════════════════════════════════════════════════════════════════════════

ENTERPRISE_DDL = [
    # ── Calculation audit log ────────────────────────────────────────────────
    """CREATE TABLE IF NOT EXISTS calc_audit_log (
        id            SERIAL PRIMARY KEY,
        formula_name  TEXT NOT NULL,
        inputs        JSONB,
        result        JSONB,
        performed_by  INTEGER,
        created_at    TIMESTAMPTZ DEFAULT NOW()
    )""",
    """CREATE INDEX IF NOT EXISTS idx_calc_audit_formula ON calc_audit_log(formula_name)""",
    """CREATE INDEX IF NOT EXISTS idx_calc_audit_ts ON calc_audit_log(created_at DESC)""",

    # ── COGS Ledger ──────────────────────────────────────────────────────────
    """CREATE TABLE IF NOT EXISTS cogs_entries (
        id              SERIAL PRIMARY KEY,
        unit_id         INTEGER REFERENCES operational_units(id) ON DELETE SET NULL,
        season_id       INTEGER REFERENCES seasons(id) ON DELETE SET NULL,
        livestock_id    INTEGER REFERENCES livestock(id) ON DELETE SET NULL,
        entry_type      TEXT NOT NULL DEFAULT 'crop',
        component       TEXT NOT NULL,
        amount          NUMERIC NOT NULL DEFAULT 0,
        entry_date      DATE DEFAULT CURRENT_DATE,
        reference       TEXT,
        notes           TEXT,
        created_by      INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_at      TIMESTAMPTZ DEFAULT NOW()
    )""",
    """CREATE INDEX IF NOT EXISTS idx_cogs_unit ON cogs_entries(unit_id)""",
    """CREATE INDEX IF NOT EXISTS idx_cogs_season ON cogs_entries(season_id)""",
    """CREATE INDEX IF NOT EXISTS idx_cogs_type ON cogs_entries(entry_type)""",

    # ── Enterprise cost allocation rules ────────────────────────────────────
    """CREATE TABLE IF NOT EXISTS cost_allocation_rules (
        id              SERIAL PRIMARY KEY,
        name            TEXT NOT NULL,
        allocation_type TEXT NOT NULL DEFAULT 'percentage',
        cost_category   TEXT NOT NULL,
        target_type     TEXT NOT NULL DEFAULT 'unit',
        target_id       INTEGER,
        allocation_pct  NUMERIC DEFAULT 0,
        allocation_fixed NUMERIC DEFAULT 0,
        active          BOOLEAN DEFAULT TRUE,
        notes           TEXT,
        created_at      TIMESTAMPTZ DEFAULT NOW()
    )""",

    # ── Scenario models (forecasting) ────────────────────────────────────────
    """CREATE TABLE IF NOT EXISTS forecast_scenarios (
        id                  SERIAL PRIMARY KEY,
        name                TEXT NOT NULL,
        season_id           INTEGER REFERENCES seasons(id) ON DELETE SET NULL,
        scenario_type       TEXT NOT NULL DEFAULT 'expected',
        base_revenue        NUMERIC DEFAULT 0,
        base_expenses       NUMERIC DEFAULT 0,
        yield_change_pct    NUMERIC DEFAULT 0,
        price_change_pct    NUMERIC DEFAULT 0,
        fuel_change_pct     NUMERIC DEFAULT 0,
        fertiliser_change_pct NUMERIC DEFAULT 0,
        labour_change_pct   NUMERIC DEFAULT 0,
        rainfall_change_pct NUMERIC DEFAULT 0,
        fx_rate_change_pct  NUMERIC DEFAULT 0,
        notes               TEXT,
        created_by          INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_at          TIMESTAMPTZ DEFAULT NOW()
    )""",
    """CREATE INDEX IF NOT EXISTS idx_forecast_season ON forecast_scenarios(season_id)""",

    # ── Livestock KPI snapshots ──────────────────────────────────────────────
    """CREATE TABLE IF NOT EXISTS livestock_kpi_snapshots (
        id                  SERIAL PRIMARY KEY,
        livestock_id        INTEGER REFERENCES livestock(id) ON DELETE CASCADE,
        snapshot_date       DATE DEFAULT CURRENT_DATE,
        head_count          INTEGER DEFAULT 0,
        deaths              INTEGER DEFAULT 0,
        births              INTEGER DEFAULT 0,
        weight_opening_kg   NUMERIC DEFAULT 0,
        weight_closing_kg   NUMERIC DEFAULT 0,
        feed_cost           NUMERIC DEFAULT 0,
        vet_cost            NUMERIC DEFAULT 0,
        medicine_cost       NUMERIC DEFAULT 0,
        breeding_cost       NUMERIC DEFAULT 0,
        transport_cost      NUMERIC DEFAULT 0,
        labour_cost         NUMERIC DEFAULT 0,
        revenue             NUMERIC DEFAULT 0,
        notes               TEXT,
        created_at          TIMESTAMPTZ DEFAULT NOW()
    )""",
    """CREATE INDEX IF NOT EXISTS idx_ls_kpi_livestock ON livestock_kpi_snapshots(livestock_id)""",
    """CREATE INDEX IF NOT EXISTS idx_ls_kpi_date ON livestock_kpi_snapshots(snapshot_date DESC)""",

    # ── Crop production records (for analytics) ──────────────────────────────
    """CREATE TABLE IF NOT EXISTS crop_production_records (
        id                  SERIAL PRIMARY KEY,
        crop_block_id       INTEGER REFERENCES crops(id) ON DELETE CASCADE,
        season_id           INTEGER REFERENCES seasons(id) ON DELETE SET NULL,
        actual_yield_kg     NUMERIC DEFAULT 0,
        estimated_yield_kg  NUMERIC DEFAULT 0,
        revenue             NUMERIC DEFAULT 0,
        seed_cost           NUMERIC DEFAULT 0,
        fertiliser_cost     NUMERIC DEFAULT 0,
        chemical_cost       NUMERIC DEFAULT 0,
        irrigation_cost     NUMERIC DEFAULT 0,
        labour_cost         NUMERIC DEFAULT 0,
        fuel_cost           NUMERIC DEFAULT 0,
        machinery_cost      NUMERIC DEFAULT 0,
        harvest_cost        NUMERIC DEFAULT 0,
        water_mm_applied    NUMERIC DEFAULT 0,
        record_date         DATE DEFAULT CURRENT_DATE,
        notes               TEXT,
        created_by          INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_at          TIMESTAMPTZ DEFAULT NOW()
    )""",
    """CREATE INDEX IF NOT EXISTS idx_cpr_crop ON crop_production_records(crop_block_id)""",
    """CREATE INDEX IF NOT EXISTS idx_cpr_season ON crop_production_records(season_id)""",

    # ── Asset usage logs ────────────────────────────────────────────────────
    """CREATE TABLE IF NOT EXISTS asset_usage_logs (
        id              SERIAL PRIMARY KEY,
        asset_id        INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
        log_date        DATE DEFAULT CURRENT_DATE,
        hours_used      NUMERIC DEFAULT 0,
        km_travelled    NUMERIC DEFAULT 0,
        fuel_cost       NUMERIC DEFAULT 0,
        operator_id     INTEGER REFERENCES workers(id) ON DELETE SET NULL,
        unit_id         INTEGER REFERENCES operational_units(id) ON DELETE SET NULL,
        notes           TEXT,
        created_at      TIMESTAMPTZ DEFAULT NOW()
    )""",
    """CREATE INDEX IF NOT EXISTS idx_asset_usage_asset ON asset_usage_logs(asset_id)""",
    """CREATE INDEX IF NOT EXISTS idx_asset_usage_date ON asset_usage_logs(log_date DESC)""",

    # ── Labour planned hours ────────────────────────────────────────────────
    """CREATE TABLE IF NOT EXISTS labour_plans (
        id              SERIAL PRIMARY KEY,
        worker_id       INTEGER REFERENCES workers(id) ON DELETE CASCADE,
        unit_id         INTEGER REFERENCES operational_units(id) ON DELETE SET NULL,
        season_id       INTEGER REFERENCES seasons(id) ON DELETE SET NULL,
        plan_month      TEXT NOT NULL,
        planned_hours   NUMERIC DEFAULT 0,
        overtime_budget NUMERIC DEFAULT 0,
        notes           TEXT,
        created_at      TIMESTAMPTZ DEFAULT NOW()
    )""",
    """CREATE INDEX IF NOT EXISTS idx_lp_worker ON labour_plans(worker_id)""",
    """CREATE INDEX IF NOT EXISTS idx_lp_season ON labour_plans(season_id)""",
]


def init_enterprise_db():
    """Run once at startup — idempotent DDL for all enterprise extension tables."""
    DATABASE_URL = os.environ["DATABASE_URL"]
    db = psycopg2.connect(DATABASE_URL)
    cur = db.cursor()
    for ddl in ENTERPRISE_DDL:
        try:
            cur.execute(ddl)
        except Exception:
            db.rollback()
    db.commit()
    db.close()


# ═══════════════════════════════════════════════════════════════════════════════
# BLUEPRINT — ALL ENTERPRISE API ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

bp = Blueprint("enterprise", __name__, url_prefix="/api/enterprise")


def _auth():
    """Inline auth — delegates to server module helpers."""
    if not _server._validate_csrf():
        return None, jsonify({"error": "Invalid CSRF token"}), 403
    user = _server.get_current_user()
    if not user:
        return None, jsonify({"error": "Unauthorized"}), 401
    g.user = user
    return user, None, None


def _role(*roles):
    user, err, code = _auth()
    if err:
        return user, err, code
    if user["role"] not in roles:
        return None, jsonify({"error": "Forbidden"}), 403
    return user, None, None


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1 — Calculation Registry API
# ─────────────────────────────────────────────────────────────────────────────

@bp.route("/calculations/registry", methods=["GET"])
def get_formula_registry():
    user, err, code = _auth()
    if err:
        return err, code
    return jsonify({
        "formulas": CalculationRegistry.all_formulas(),
        "total": len(CalculationRegistry.all_formulas()),
    })


@bp.route("/calculations/invoke", methods=["POST"])
def invoke_formula():
    """
    POST { "formula": "gross_profit", "inputs": { "revenue": 10000, "cogs": 4000 } }
    """
    user, err, code = _auth()
    if err:
        return err, code
    d = request.get_json() or {}
    formula_name = d.get("formula")
    inputs = d.get("inputs", {})
    if not formula_name:
        return jsonify({"error": "formula is required"}), 400
    try:
        result = CalculationRegistry.invoke(formula_name, **inputs)
    except KeyError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": f"Calculation error: {e}"}), 422
    _log_calculation_audit(formula_name, inputs, result, user["id"])
    return jsonify({"formula": formula_name, "inputs": inputs, "result": result})


@bp.route("/calculations/audit", methods=["GET"])
def get_calc_audit():
    user, err, code = _role("owner", "manager", "finance")
    if err:
        return err, code
    limit = int(request.args.get("limit", 100))
    rows = _q(
        "SELECT * FROM calc_audit_log ORDER BY created_at DESC LIMIT %s",
        (limit,)
    )
    return jsonify(_rows(rows))


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2 — Enterprise Cost Accounting
# ─────────────────────────────────────────────────────────────────────────────

@bp.route("/cost-accounting/enterprise-summary", methods=["GET"])
def enterprise_cost_summary():
    """
    Per-unit P&L: Revenue, Expenses, Gross Profit, Net Profit, Profit/ha.
    Supports: field, herd, greenhouse, orchard, warehouse, silo.
    """
    user, err, code = _auth()
    if err:
        return err, code
    season_id = request.args.get("season_id")

    season_filter = "AND a.season_id=%s" if season_id else ""
    season_args = (season_id,) if season_id else ()

    units = _q("""
        SELECT u.id, u.name, u.unit_type, u.area_ha,
               COALESCE(SUM(a.total_cost),0) AS direct_costs,
               COALESCE(SUM(pb.actual_revenue),0) AS revenue,
               COALESCE(SUM(pb.quantity),0) AS production_qty
        FROM operational_units u
        LEFT JOIN operational_activities a ON a.unit_id=u.id AND a.status='Completed' """ + season_filter + """
        LEFT JOIN production_batches pb ON pb.unit_id=u.id """ + ("AND pb.season_id=%s" if season_id else "") + """
        WHERE u.active=TRUE
        GROUP BY u.id, u.name, u.unit_type, u.area_ha
        ORDER BY revenue DESC
    """, season_args + (season_args[0:1] if season_id else ()))

    result = []
    for row in _rows(units):
        rev = _float(row["revenue"])
        direct = _float(row["direct_costs"])
        area = _float(row["area_ha"]) or 1

        # Pull labour cost for this unit
        lab = _q(
            "SELECT COALESCE(SUM(la.hours * la.hourly_rate),0) AS lc FROM labor_allocations la WHERE la.unit_id=%s",
            (row["id"],), one=True
        )
        labour_cost = _float(lab["lc"]) if lab else 0.0

        # Pull COGS entries for this unit
        cogs_row = _q(
            "SELECT COALESCE(SUM(amount),0) AS cogs FROM cogs_entries WHERE unit_id=%s" +
            (" AND season_id=%s" if season_id else ""),
            (row["id"],) + ((season_id,) if season_id else ()), one=True
        )
        cogs = _float(cogs_row["cogs"]) if cogs_row else 0.0

        total_costs = direct + labour_cost + cogs
        gross_profit = FinanceCalculator.gross_profit(rev, total_costs)

        row.update({
            "labour_cost": labour_cost,
            "cogs": cogs,
            "total_costs": total_costs,
            "gross_profit": gross_profit,
            "net_profit": gross_profit,  # Operating = Gross before shared allocation
            "profit_per_ha": CropCalculator.profit_per_ha(gross_profit, area),
            "gross_margin_pct": FinanceCalculator.gross_margin_pct(rev, total_costs),
            "cost_per_ha": CropCalculator.cost_per_ha(total_costs, area),
        })
        result.append(row)
    return jsonify(result)


@bp.route("/cost-accounting/allocation-rules", methods=["GET"])
def get_allocation_rules():
    user, err, code = _auth()
    if err:
        return err, code
    return jsonify(_rows(_q("SELECT * FROM cost_allocation_rules WHERE active=TRUE ORDER BY name")))


@bp.route("/cost-accounting/allocation-rules", methods=["POST"])
def create_allocation_rule():
    user, err, code = _role("owner", "manager", "finance")
    if err:
        return err, code
    d = request.get_json() or {}
    rid = _m(
        """INSERT INTO cost_allocation_rules
           (name,allocation_type,cost_category,target_type,target_id,allocation_pct,allocation_fixed,notes)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
        (d["name"], d.get("allocation_type","percentage"), d["cost_category"],
         d.get("target_type","unit"), d.get("target_id"), d.get("allocation_pct",0),
         d.get("allocation_fixed",0), d.get("notes"))
    )
    return jsonify(_row(_q("SELECT * FROM cost_allocation_rules WHERE id=%s", (rid,), one=True))), 201


@bp.route("/cost-accounting/allocation-rules/<int:rid>", methods=["PUT"])
def update_allocation_rule(rid):
    user, err, code = _role("owner", "manager", "finance")
    if err:
        return err, code
    d = request.get_json() or {}
    _m(
        """UPDATE cost_allocation_rules
           SET name=%s, cost_category=%s, allocation_pct=%s, allocation_fixed=%s, notes=%s
           WHERE id=%s""",
        (d["name"], d["cost_category"], d.get("allocation_pct",0), d.get("allocation_fixed",0), d.get("notes"), rid)
    )
    return jsonify(_row(_q("SELECT * FROM cost_allocation_rules WHERE id=%s", (rid,), one=True)))


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3 — COGS Ledger
# ─────────────────────────────────────────────────────────────────────────────

@bp.route("/cogs", methods=["GET"])
def get_cogs_entries():
    user, err, code = _auth()
    if err:
        return err, code
    unit_id = request.args.get("unit_id")
    season_id = request.args.get("season_id")
    entry_type = request.args.get("entry_type")

    conditions, args = [], []
    if unit_id:
        conditions.append("c.unit_id=%s"); args.append(unit_id)
    if season_id:
        conditions.append("c.season_id=%s"); args.append(season_id)
    if entry_type:
        conditions.append("c.entry_type=%s"); args.append(entry_type)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    rows = _q(
        f"""SELECT c.*, u.name as unit_name, s.name as season_name
            FROM cogs_entries c
            LEFT JOIN operational_units u ON c.unit_id=u.id
            LEFT JOIN seasons s ON c.season_id=s.id
            {where}
            ORDER BY c.entry_date DESC""",
        tuple(args)
    )
    return jsonify(_rows(rows))


@bp.route("/cogs", methods=["POST"])
def create_cogs_entry():
    user, err, code = _role("owner", "manager", "finance")
    if err:
        return err, code
    d = request.get_json() or {}
    if not d.get("component") or not d.get("amount"):
        return jsonify({"error": "component and amount are required"}), 400
    eid = _m(
        """INSERT INTO cogs_entries
           (unit_id,season_id,livestock_id,entry_type,component,amount,entry_date,reference,notes,created_by)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
        (d.get("unit_id"), d.get("season_id"), d.get("livestock_id"),
         d.get("entry_type","crop"), d["component"], d["amount"],
         d.get("entry_date", date.today().isoformat()),
         d.get("reference"), d.get("notes"), user["id"])
    )
    return jsonify(_row(_q("SELECT * FROM cogs_entries WHERE id=%s", (eid,), one=True))), 201


@bp.route("/cogs/<int:eid>", methods=["DELETE"])
def delete_cogs_entry(eid):
    user, err, code = _role("owner", "manager", "finance")
    if err:
        return err, code
    _m("DELETE FROM cogs_entries WHERE id=%s", (eid,))
    return jsonify({"deleted": eid})


@bp.route("/cogs/summary", methods=["GET"])
def cogs_summary():
    """COGS breakdown by type + component, and derived gross profit."""
    user, err, code = _auth()
    if err:
        return err, code
    season_id = request.args.get("season_id")
    filter_sql = "WHERE season_id=%s" if season_id else ""
    args = (season_id,) if season_id else ()

    breakdown = _q(
        f"""SELECT entry_type, component, SUM(amount) AS total
            FROM cogs_entries {filter_sql}
            GROUP BY entry_type, component
            ORDER BY entry_type, total DESC""",
        args
    )

    total_cogs_row = _q(
        f"SELECT COALESCE(SUM(amount),0) AS total FROM cogs_entries {filter_sql}", args, one=True
    )
    total_revenue = _q(
        "SELECT COALESCE(SUM(amount),0) AS total FROM finance WHERE type='income'", one=True
    )
    total_cogs = _float(total_cogs_row["total"])
    rev = _float(total_revenue["total"])

    return jsonify({
        "breakdown": _rows(breakdown),
        "total_cogs": total_cogs,
        "total_revenue": rev,
        "gross_profit": FinanceCalculator.gross_profit(rev, total_cogs),
        "gross_margin_pct": FinanceCalculator.gross_margin_pct(rev, total_cogs),
    })


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 4 — Advanced Farm Profitability
# ─────────────────────────────────────────────────────────────────────────────

@bp.route("/profitability/advanced", methods=["GET"])
def advanced_profitability():
    """
    Full P&L waterfall:
    Revenue → COGS → Gross Profit → OpEx → Operating Profit → EBITDA → Net Profit.
    Drill-down available by unit, season, or enterprise type.
    """
    user, err, code = _auth()
    if err:
        return err, code
    season_id = request.args.get("season_id")

    # ── Revenue ──────────────────────────────────────────────────────────────
    rev_row = _q("SELECT COALESCE(SUM(amount),0) AS total FROM finance WHERE type='income'", one=True)
    revenue = _float(rev_row["total"])

    # ── COGS ─────────────────────────────────────────────────────────────────
    cogs_filter = "WHERE season_id=%s" if season_id else ""
    cogs_args = (season_id,) if season_id else ()
    cogs_row = _q(f"SELECT COALESCE(SUM(amount),0) AS total FROM cogs_entries {cogs_filter}", cogs_args, one=True)
    cogs = _float(cogs_row["total"])

    # ── Operating expenses ────────────────────────────────────────────────────
    opex_row = _q("SELECT COALESCE(SUM(amount),0) AS total FROM finance WHERE type='expense'", one=True)
    opex = _float(opex_row["total"])

    # ── Activity costs ────────────────────────────────────────────────────────
    act_row = _q("SELECT COALESCE(SUM(total_cost),0) AS total FROM operational_activities WHERE status='Completed'", one=True)
    activity_costs = _float(act_row["total"])

    # ── Labour costs ─────────────────────────────────────────────────────────
    lab_row = _q("SELECT COALESCE(SUM(hours*hourly_rate),0) AS total FROM labor_allocations", one=True)
    labour_cost = _float(lab_row["total"])

    # ── Depreciation ─────────────────────────────────────────────────────────
    dep_row = _q("SELECT COALESCE(SUM(annual_depreciation),0) AS total FROM asset_depreciation", one=True)
    depreciation = _float(dep_row["total"])

    # ── Workers (for per-worker metrics) ─────────────────────────────────────
    wk_row = _q("SELECT COUNT(*) AS cnt FROM workers WHERE status='Present'", one=True)
    worker_count = int(wk_row["cnt"]) if wk_row else 1

    # ── Total hectares ────────────────────────────────────────────────────────
    ha_row = _q("SELECT COALESCE(SUM(area_ha),0) AS total FROM operational_units WHERE active=TRUE", one=True)
    total_ha = _float(ha_row["total"]) or 1

    # ── Livestock count ───────────────────────────────────────────────────────
    ls_row = _q("SELECT COALESCE(SUM(count),0) AS total FROM livestock", one=True)
    livestock_count = int(_float(ls_row["total"])) or 1

    # ── Contingency ──────────────────────────────────────────────────────────
    cont = _q("SELECT * FROM contingency_settings ORDER BY id DESC LIMIT 1", one=True)
    contingency = 0.0
    if cont:
        if cont["contingency_type"] == "percentage":
            contingency = opex * _float(cont["contingency_pct"]) / 100
        else:
            contingency = _float(cont["contingency_fixed"])

    total_opex = opex + activity_costs + labour_cost
    gross_profit = FinanceCalculator.gross_profit(revenue, cogs)
    operating_profit = FinanceCalculator.operating_profit(gross_profit, total_opex)
    ebitda_val = FinanceCalculator.ebitda(operating_profit, depreciation)

    # Simplified: no external interest/tax — use contingency as tax proxy
    net_profit_val = FinanceCalculator.net_profit(ebitda_val, 0, contingency)

    return jsonify({
        "revenue": revenue,
        "cogs": cogs,
        "gross_profit": gross_profit,
        "gross_margin_pct": FinanceCalculator.gross_margin_pct(revenue, cogs),
        "operating_expenses": total_opex,
        "activity_costs": activity_costs,
        "labour_cost": labour_cost,
        "depreciation": depreciation,
        "operating_profit": operating_profit,
        "ebitda": ebitda_val,
        "ebitda_margin_pct": ProfitabilityCalculator.ebitda_margin(ebitda_val, revenue),
        "contingency_provision": contingency,
        "net_profit": net_profit_val,
        "net_margin_pct": ProfitabilityCalculator.net_margin(net_profit_val, revenue),
        "adjusted_profit": FinanceCalculator.adjusted_profit(net_profit_val, contingency),
        # Per-unit metrics
        "profit_per_ha": CropCalculator.profit_per_ha(net_profit_val, total_ha),
        "profit_per_animal": LivestockCalculator.profit_per_head(net_profit_val, livestock_count),
        "profit_per_worker": ProfitabilityCalculator.profit_per_worker(net_profit_val, worker_count),
        "revenue_per_ha": CropCalculator.revenue_per_ha(revenue, total_ha),
        "cost_per_ha": CropCalculator.cost_per_ha(total_opex + cogs, total_ha),
    })


@bp.route("/profitability/by-enterprise", methods=["GET"])
def profitability_by_enterprise():
    """Drill-down: per unit_type P&L (field, herd, greenhouse, etc.)"""
    user, err, code = _auth()
    if err:
        return err, code
    rows = _q("""
        SELECT u.unit_type,
               COALESCE(SUM(pb.actual_revenue),0) AS revenue,
               COALESCE(SUM(a.total_cost),0) AS costs
        FROM operational_units u
        LEFT JOIN production_batches pb ON pb.unit_id=u.id
        LEFT JOIN operational_activities a ON a.unit_id=u.id AND a.status='Completed'
        WHERE u.active=TRUE
        GROUP BY u.unit_type ORDER BY revenue DESC
    """)
    result = []
    for r in _rows(rows):
        rev = _float(r["revenue"])
        costs = _float(r["costs"])
        gp = FinanceCalculator.gross_profit(rev, costs)
        r["gross_profit"] = gp
        r["margin_pct"] = FinanceCalculator.gross_margin_pct(rev, costs)
        result.append(r)
    return jsonify(result)


@bp.route("/profitability/by-season", methods=["GET"])
def profitability_by_season():
    """Season-over-season profitability comparison."""
    user, err, code = _auth()
    if err:
        return err, code
    rows = _q("""
        SELECT s.id, s.name, s.start_date, s.end_date,
               COALESCE(SUM(pb.actual_revenue),0) AS revenue,
               COALESCE(SUM(a.total_cost),0) AS activity_costs,
               COALESCE(SUM(b.planned_amount),0) AS budget
        FROM seasons s
        LEFT JOIN production_batches pb ON pb.season_id=s.id
        LEFT JOIN operational_activities a ON a.season_id=s.id AND a.status='Completed'
        LEFT JOIN budgets b ON b.season_id=s.id
        GROUP BY s.id, s.name, s.start_date, s.end_date
        ORDER BY s.start_date DESC
    """)
    result = []
    for r in _rows(rows):
        rev = _float(r["revenue"])
        costs = _float(r["activity_costs"])
        budget = _float(r["budget"])
        gp = FinanceCalculator.gross_profit(rev, costs)
        r.update({
            "gross_profit": gp,
            "margin_pct": FinanceCalculator.gross_margin_pct(rev, costs),
            "budget_utilisation_pct": BudgetCalculator.budget_utilisation_pct(costs, budget),
            "budget_variance": BudgetCalculator.budget_variance(budget, costs),
        })
        result.append(r)
    return jsonify(result)


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 5 — Forecasting & Scenario Modelling
# ─────────────────────────────────────────────────────────────────────────────

@bp.route("/forecasting/scenarios", methods=["GET"])
def get_scenarios():
    user, err, code = _auth()
    if err:
        return err, code
    season_id = request.args.get("season_id")
    if season_id:
        rows = _q(
            "SELECT fs.*, s.name as season_name FROM forecast_scenarios fs LEFT JOIN seasons s ON fs.season_id=s.id WHERE fs.season_id=%s ORDER BY fs.created_at DESC",
            (season_id,)
        )
    else:
        rows = _q("SELECT fs.*, s.name as season_name FROM forecast_scenarios fs LEFT JOIN seasons s ON fs.season_id=s.id ORDER BY fs.created_at DESC")
    return jsonify(_rows(rows))


@bp.route("/forecasting/scenarios", methods=["POST"])
def create_scenario():
    user, err, code = _role("owner", "manager", "finance")
    if err:
        return err, code
    d = request.get_json() or {}
    if not d.get("name"):
        return jsonify({"error": "name is required"}), 400
    sid = _m(
        """INSERT INTO forecast_scenarios
           (name,season_id,scenario_type,base_revenue,base_expenses,
            yield_change_pct,price_change_pct,fuel_change_pct,
            fertiliser_change_pct,labour_change_pct,rainfall_change_pct,
            fx_rate_change_pct,notes,created_by)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
        (d["name"], d.get("season_id"), d.get("scenario_type","expected"),
         d.get("base_revenue",0), d.get("base_expenses",0),
         d.get("yield_change_pct",0), d.get("price_change_pct",0),
         d.get("fuel_change_pct",0), d.get("fertiliser_change_pct",0),
         d.get("labour_change_pct",0), d.get("rainfall_change_pct",0),
         d.get("fx_rate_change_pct",0), d.get("notes"), user["id"])
    )
    return jsonify(_row(_q("SELECT * FROM forecast_scenarios WHERE id=%s", (sid,), one=True))), 201


@bp.route("/forecasting/scenarios/<int:sid>/run", methods=["POST"])
def run_scenario(sid):
    """Calculate projected P&L for a saved scenario."""
    user, err, code = _auth()
    if err:
        return err, code
    sc = _q("SELECT * FROM forecast_scenarios WHERE id=%s", (sid,), one=True)
    if not sc:
        return jsonify({"error": "Scenario not found"}), 404
    sc = dict(sc)

    base_rev = _float(sc["base_revenue"])
    base_exp = _float(sc["base_expenses"])

    if not base_rev:
        rev_row = _q("SELECT COALESCE(SUM(amount),0) AS t FROM finance WHERE type='income'", one=True)
        base_rev = _float(rev_row["t"])
    if not base_exp:
        exp_row = _q("SELECT COALESCE(SUM(amount),0) AS t FROM finance WHERE type='expense'", one=True)
        base_exp = _float(exp_row["t"])

    projected_revenue = ForecastCalculator.scenario_revenue(
        base_rev, _float(sc["yield_change_pct"]), _float(sc["price_change_pct"])
    )
    projected_expenses = ForecastCalculator.scenario_expenses(
        base_exp,
        fuel_change_pct=_float(sc["fuel_change_pct"]),
        fertiliser_change_pct=_float(sc["fertiliser_change_pct"]),
        labour_change_pct=_float(sc["labour_change_pct"]),
    )
    projected_profit = FinanceCalculator.gross_profit(projected_revenue, projected_expenses)
    base_profit = FinanceCalculator.gross_profit(base_rev, base_exp)

    return jsonify({
        "scenario": sc,
        "base_revenue": base_rev,
        "base_expenses": base_exp,
        "base_profit": base_profit,
        "projected_revenue": projected_revenue,
        "projected_expenses": projected_expenses,
        "projected_profit": projected_profit,
        "revenue_impact": round(projected_revenue - base_rev, 2),
        "expense_impact": round(projected_expenses - base_exp, 2),
        "profit_impact": round(projected_profit - base_profit, 2),
        "projected_margin_pct": FinanceCalculator.gross_margin_pct(projected_revenue, projected_expenses),
        "projected_roi": FinanceCalculator.roi(projected_profit, projected_expenses),
    })


@bp.route("/forecasting/what-if", methods=["POST"])
def what_if_analysis():
    """
    Ad-hoc what-if without saving a scenario.
    POST { "base_revenue": ..., "base_expenses": ..., <change params> }
    """
    user, err, code = _auth()
    if err:
        return err, code
    d = request.get_json() or {}

    # Fall back to actual figures if base not supplied
    if not d.get("base_revenue"):
        r = _q("SELECT COALESCE(SUM(amount),0) AS t FROM finance WHERE type='income'", one=True)
        d["base_revenue"] = _float(r["t"])
    if not d.get("base_expenses"):
        e = _q("SELECT COALESCE(SUM(amount),0) AS t FROM finance WHERE type='expense'", one=True)
        d["base_expenses"] = _float(e["t"])

    scenarios = {}
    # Run all three cases
    for label, multipliers in [
        ("worst_case", {"yield": -20, "price": -15, "fuel": 20, "fertiliser": 15, "labour": 10}),
        ("expected_case", {"yield": 0, "price": 0, "fuel": 0, "fertiliser": 0, "labour": 0}),
        ("best_case", {"yield": 15, "price": 10, "fuel": -5, "fertiliser": -5, "labour": 0}),
    ]:
        yield_chg = d.get("yield_change_pct", multipliers["yield"])
        price_chg = d.get("price_change_pct", multipliers["price"])
        fuel_chg = d.get("fuel_change_pct", multipliers["fuel"])
        fert_chg = d.get("fertiliser_change_pct", multipliers["fertiliser"])
        lab_chg = d.get("labour_change_pct", multipliers["labour"])

        proj_rev = ForecastCalculator.scenario_revenue(d["base_revenue"], yield_chg, price_chg)
        proj_exp = ForecastCalculator.scenario_expenses(d["base_expenses"], fuel_chg, fert_chg, lab_chg)
        profit = FinanceCalculator.gross_profit(proj_rev, proj_exp)
        scenarios[label] = {
            "revenue": proj_rev,
            "expenses": proj_exp,
            "profit": profit,
            "margin_pct": FinanceCalculator.gross_margin_pct(proj_rev, proj_exp),
            "yield_change_pct": yield_chg,
            "price_change_pct": price_chg,
        }

    # Apply user-supplied overrides if passed
    if any(k in d for k in ["yield_change_pct", "price_change_pct"]):
        custom_rev = ForecastCalculator.scenario_revenue(
            d["base_revenue"], d.get("yield_change_pct", 0), d.get("price_change_pct", 0)
        )
        custom_exp = ForecastCalculator.scenario_expenses(
            d["base_expenses"],
            d.get("fuel_change_pct", 0),
            d.get("fertiliser_change_pct", 0),
            d.get("labour_change_pct", 0),
        )
        profit = FinanceCalculator.gross_profit(custom_rev, custom_exp)
        scenarios["custom"] = {
            "revenue": custom_rev,
            "expenses": custom_exp,
            "profit": profit,
            "margin_pct": FinanceCalculator.gross_margin_pct(custom_rev, custom_exp),
        }

    return jsonify({
        "base_revenue": d["base_revenue"],
        "base_expenses": d["base_expenses"],
        "base_profit": FinanceCalculator.gross_profit(d["base_revenue"], d["base_expenses"]),
        "scenarios": scenarios,
    })


@bp.route("/forecasting/cashflow", methods=["GET"])
def cashflow_forecast():
    """12-month forward cashflow forecast based on trailing 6-month averages."""
    user, err, code = _auth()
    if err:
        return err, code
    months = int(request.args.get("months", 12))

    hist = _q("""
        SELECT
            AVG(CASE WHEN type='income'  THEN amount END) AS avg_monthly_income,
            AVG(CASE WHEN type='expense' THEN amount END) AS avg_monthly_expense
        FROM finance
        WHERE TO_DATE(date,'YYYY-MM-DD') >= CURRENT_DATE - INTERVAL '6 months'
    """, one=True)
    avg_income = _float(hist["avg_monthly_income"]) if hist else 0.0
    avg_expense = _float(hist["avg_monthly_expense"]) if hist else 0.0

    # Current bank balance proxy
    bal_row = _q("SELECT COALESCE(SUM(CASE WHEN type='income' THEN amount ELSE -amount END),0) AS bal FROM finance", one=True)
    opening = _float(bal_row["bal"])

    forecast_months = []
    balance = opening
    for i in range(1, months + 1):
        month_label = (date.today().replace(day=1) + timedelta(days=32 * i)).strftime("%Y-%m")
        month = ForecastCalculator.cashflow_forecast_month(avg_income, avg_expense, balance)
        month["month"] = month_label
        balance = month["closing_balance"]
        forecast_months.append(month)

    return jsonify({
        "avg_monthly_income": avg_income,
        "avg_monthly_expense": avg_expense,
        "opening_balance": opening,
        "forecast": forecast_months,
    })


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 6 — Inventory Optimisation Engine
# ─────────────────────────────────────────────────────────────────────────────

@bp.route("/inventory/optimisation", methods=["GET"])
def inventory_optimisation():
    """
    Per-item: EOQ, ROP, Safety Stock, Days Remaining, ABC class,
    turnover, WAVG cost, fast/slow/dead stock classification.
    """
    user, err, code = _auth()
    if err:
        return err, code
    items = _q("""
        SELECT i.*,
               COALESCE(
                   (SELECT SUM(ic.quantity_used) FROM inventory_consumption ic WHERE ic.inventory_id=i.id),
               0) AS total_consumed,
               COALESCE(
                   (SELECT COUNT(DISTINCT DATE_TRUNC('month',a.activity_date))
                    FROM inventory_consumption ic2
                    JOIN operational_activities a ON ic2.activity_id=a.id
                    WHERE ic2.inventory_id=i.id
                    AND a.activity_date >= CURRENT_DATE - INTERVAL '6 months'),
               0) AS active_months
        FROM inventory i
        ORDER BY (i.on_hand * i.unit_cost) DESC
    """)

    # ABC analysis: sort by descending value, assign cumulative % then A/B/C
    items_list = _rows(items)
    total_val = sum(_float(r["on_hand"]) * _float(r["unit_cost"]) for r in items_list) or 1
    cumulative = 0.0
    for r in items_list:
        item_val = _float(r["on_hand"]) * _float(r["unit_cost"])
        val_pct = item_val / total_val * 100
        cumulative += val_pct
        r["value"] = round(item_val, 2)
        r["value_pct"] = round(val_pct, 2)
        r["cumulative_value_pct"] = round(cumulative, 2)
        r["abc_class"] = InventoryCalculator.abc_classification(cumulative)

        period_days = 180  # 6 months
        total_consumed = _float(r["total_consumed"])
        avg_daily = InventoryCalculator.avg_daily_consumption(total_consumed, period_days)
        r["avg_daily_consumption"] = avg_daily

        on_hand = _float(r["on_hand"])
        r["days_remaining"] = InventoryCalculator.days_inventory_remaining(on_hand, avg_daily)

        # Lead time from par_level proxy: max_level - par_level / avg_daily
        lead_time = _float(r.get("max_level", 0)) / avg_daily if avg_daily else 14
        r["lead_time_days"] = round(lead_time, 1)
        safety = InventoryCalculator.safety_stock(1.645, avg_daily * 0.3, lead_time)
        r["safety_stock"] = safety
        r["reorder_point"] = InventoryCalculator.reorder_point(avg_daily, lead_time, safety)

        # EOQ (assume order cost = 5% of unit_cost, holding = 25%)
        order_cost = _float(r["unit_cost"]) * 0.05 + 5
        annual_demand = avg_daily * 365
        r["eoq"] = InventoryCalculator.economic_order_quantity(annual_demand, order_cost, 0.25, _float(r["unit_cost"]))

        # Movement classification
        active_months = int(r.get("active_months", 0))
        if active_months >= 4:
            r["movement_class"] = "Fast Moving"
        elif active_months >= 1:
            r["movement_class"] = "Slow Moving"
        else:
            r["movement_class"] = "Dead Stock"

        # Reorder recommendation
        r["reorder_recommended"] = on_hand <= r["reorder_point"]

        # Valuation methods (lot-based FIFO and WAVG)
        lots = _q(
            "SELECT quantity_remaining, unit_cost FROM inventory_lots WHERE inventory_id=%s AND quantity_remaining>0 ORDER BY received_date ASC",
            (r["id"],)
        )
        lots_list = [((_float(l["quantity_remaining"]), _float(l["unit_cost"]))) for l in lots]
        r["fifo_value"] = round(sum(q * c for q, c in lots_list), 2) if lots_list else round(on_hand * _float(r["unit_cost"]), 2)
        r["wavg_cost"] = InventoryCalculator.weighted_avg_cost(lots_list) if lots_list else _float(r["unit_cost"])
        r["wavg_value"] = round(on_hand * r["wavg_cost"], 2)

        # Ageing: days since last lot received
        last_lot = _q(
            "SELECT MAX(received_date) AS last FROM inventory_lots WHERE inventory_id=%s",
            (r["id"],), one=True
        )
        if last_lot and last_lot["last"]:
            age_days = (date.today() - last_lot["last"]).days
            r["stock_age_days"] = age_days
        else:
            r["stock_age_days"] = None

    # Turnover: total consumed value / avg inventory value
    total_consumed_val = sum(_float(r["total_consumed"]) * _float(r["unit_cost"]) for r in items_list)
    avg_inv_val = total_val
    overall_turnover = InventoryCalculator.inventory_turnover(total_consumed_val, avg_inv_val)

    return jsonify({
        "items": items_list,
        "total_inventory_value": round(total_val, 2),
        "total_consumed_value": round(total_consumed_val, 2),
        "inventory_turnover": overall_turnover,
        "items_below_reorder": sum(1 for r in items_list if r["reorder_recommended"]),
        "dead_stock_count": sum(1 for r in items_list if r["movement_class"] == "Dead Stock"),
        "purchasing_recommendations": [
            {
                "id": r["id"],
                "name": r["name"],
                "on_hand": r["on_hand"],
                "reorder_point": r["reorder_point"],
                "eoq": r["eoq"],
                "urgency": "Critical" if _float(r["on_hand"]) <= _float(r.get("par_level",0)) else "Scheduled",
            }
            for r in items_list if r["reorder_recommended"]
        ],
    })


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 7 — Livestock Analytics
# ─────────────────────────────────────────────────────────────────────────────

@bp.route("/livestock/analytics", methods=["GET"])
def livestock_analytics():
    user, err, code = _auth()
    if err:
        return err, code

    herds = _q("SELECT * FROM livestock ORDER BY herd_name")
    result = []
    for h in _rows(herds):
        hid = h["id"]
        head_count = int(h["count"]) or 1

        # KPI snapshots for this herd
        snaps = _q(
            "SELECT * FROM livestock_kpi_snapshots WHERE livestock_id=%s ORDER BY snapshot_date DESC LIMIT 12",
            (hid,)
        )
        snaps_list = _rows(snaps)

        if snaps_list:
            latest = snaps_list[0]
            feed_cost = _float(latest["feed_cost"])
            vet_cost = _float(latest["vet_cost"])
            medicine_cost = _float(latest["medicine_cost"])
            breeding_cost = _float(latest["breeding_cost"])
            transport_cost = _float(latest["transport_cost"])
            labour_cost = _float(latest["labour_cost"])
            revenue = _float(latest["revenue"])
            deaths = int(latest["deaths"]) if latest["deaths"] else 0
            births = int(latest["births"]) if latest["births"] else 0
            w_open = _float(latest["weight_opening_kg"])
            w_close = _float(latest["weight_closing_kg"])
        else:
            # Fall back to activity costs tagged to this herd's unit
            feed_cost = vet_cost = medicine_cost = breeding_cost = transport_cost = labour_cost = 0.0
            revenue = 0.0
            deaths = births = 0
            w_open = w_close = 0.0

        total_cogs = LivestockCalculator.total_livestock_cogs(
            feed_cost, vet_cost, breeding_cost, labour_cost, medicine_cost, transport_cost
        )
        gross_profit = FinanceCalculator.gross_profit(revenue, total_cogs)

        weight_gain = w_close - w_open
        feed_consumed = feed_cost / max(_float(h.get("avg_weight", 1)), 1)  # proxy

        kpis = {
            "feed_cost_per_head": LivestockCalculator.feed_cost_per_head(feed_cost, head_count),
            "vet_cost_per_head": LivestockCalculator.vet_cost_per_head(vet_cost, head_count),
            "revenue_per_head": LivestockCalculator.revenue_per_head(revenue, head_count),
            "profit_per_head": LivestockCalculator.profit_per_head(gross_profit, head_count),
            "mortality_rate_pct": LivestockCalculator.mortality_rate(deaths, head_count + deaths),
            "birth_rate_pct": LivestockCalculator.birth_rate(births, max(head_count // 2, 1)),
            "feed_conversion_ratio": LivestockCalculator.feed_conversion_ratio(feed_consumed, weight_gain) if weight_gain > 0 else None,
            "gross_profit": gross_profit,
            "total_cogs": total_cogs,
            "gross_margin_pct": FinanceCalculator.gross_margin_pct(revenue, total_cogs),
        }
        h["kpis"] = kpis
        h["snapshots"] = snaps_list
        result.append(h)

    return jsonify(result)


@bp.route("/livestock/kpi-snapshots", methods=["POST"])
def create_livestock_kpi_snapshot():
    user, err, code = _role("owner", "manager", "field")
    if err:
        return err, code
    d = request.get_json() or {}
    if not d.get("livestock_id"):
        return jsonify({"error": "livestock_id is required"}), 400
    snap_id = _m(
        """INSERT INTO livestock_kpi_snapshots
           (livestock_id,snapshot_date,head_count,deaths,births,
            weight_opening_kg,weight_closing_kg,feed_cost,vet_cost,
            medicine_cost,breeding_cost,transport_cost,labour_cost,revenue,notes)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
        (d["livestock_id"], d.get("snapshot_date", date.today().isoformat()),
         d.get("head_count",0), d.get("deaths",0), d.get("births",0),
         d.get("weight_opening_kg",0), d.get("weight_closing_kg",0),
         d.get("feed_cost",0), d.get("vet_cost",0), d.get("medicine_cost",0),
         d.get("breeding_cost",0), d.get("transport_cost",0), d.get("labour_cost",0),
         d.get("revenue",0), d.get("notes"))
    )
    return jsonify(_row(_q("SELECT * FROM livestock_kpi_snapshots WHERE id=%s", (snap_id,), one=True))), 201


@bp.route("/livestock/kpi-snapshots/<int:lid>", methods=["GET"])
def get_livestock_kpi_snapshots(lid):
    user, err, code = _auth()
    if err:
        return err, code
    rows = _q(
        "SELECT * FROM livestock_kpi_snapshots WHERE livestock_id=%s ORDER BY snapshot_date DESC",
        (lid,)
    )
    return jsonify(_rows(rows))


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 8 — Crop Analytics
# ─────────────────────────────────────────────────────────────────────────────

@bp.route("/crops/analytics", methods=["GET"])
def crop_analytics():
    user, err, code = _auth()
    if err:
        return err, code

    rows = _q("""
        SELECT c.id, c.block, c.crop, c.area_ha, c.planted, c.est_harvest, c.status,
               c.irrigation, c.est_yield_value,
               pr.actual_yield_kg, pr.estimated_yield_kg, pr.revenue,
               pr.seed_cost, pr.fertiliser_cost, pr.chemical_cost,
               pr.irrigation_cost, pr.labour_cost, pr.fuel_cost,
               pr.machinery_cost, pr.harvest_cost, pr.water_mm_applied,
               pr.record_date, pr.season_id
        FROM crops c
        LEFT JOIN crop_production_records pr ON pr.crop_block_id=c.id
        ORDER BY c.block
    """)
    result = []
    seen = {}
    for r in _rows(rows):
        cid = r["id"]
        area = _float(r["area_ha"]) or 1
        actual_yield = _float(r["actual_yield_kg"])
        est_yield = _float(r["estimated_yield_kg"]) or _float(r["est_yield_value"])
        revenue = _float(r["revenue"])

        variable_costs = (
            _float(r["seed_cost"]) + _float(r["fertiliser_cost"]) +
            _float(r["chemical_cost"]) + _float(r["irrigation_cost"]) +
            _float(r["labour_cost"]) + _float(r["fuel_cost"]) +
            _float(r["machinery_cost"]) + _float(r["harvest_cost"])
        )

        analytics = {
            "yield_per_ha": CropCalculator.yield_per_ha(actual_yield, area),
            "estimated_yield_per_ha": CropCalculator.yield_per_ha(est_yield, area),
            "yield_variance_pct": CropCalculator.yield_variance_pct(actual_yield, est_yield),
            "revenue_per_ha": CropCalculator.revenue_per_ha(revenue, area),
            "cost_per_ha": CropCalculator.cost_per_ha(variable_costs, area),
            "profit_per_ha": CropCalculator.profit_per_ha(revenue - variable_costs, area),
            "gross_margin": CropCalculator.crop_gross_margin(revenue, variable_costs),
            "net_margin_pct": ProfitabilityCalculator.net_margin(revenue - variable_costs, revenue),
            "water_use_efficiency": CropCalculator.water_use_efficiency(actual_yield, _float(r["water_mm_applied"])) if r["water_mm_applied"] else None,
            "input_cost_per_ha": CropCalculator.input_cost_per_ha(
                _float(r["seed_cost"]), _float(r["fertiliser_cost"]),
                _float(r["chemical_cost"]), _float(r["irrigation_cost"]), area
            ),
            "total_variable_cost": round(variable_costs, 2),
        }
        r["analytics"] = analytics
        if cid not in seen:
            seen[cid] = r
            result.append(r)

    return jsonify(result)


@bp.route("/crops/production-records", methods=["GET"])
def get_crop_production_records():
    user, err, code = _auth()
    if err:
        return err, code
    crop_id = request.args.get("crop_id")
    season_id = request.args.get("season_id")
    conditions, args = [], []
    if crop_id:
        conditions.append("pr.crop_block_id=%s"); args.append(crop_id)
    if season_id:
        conditions.append("pr.season_id=%s"); args.append(season_id)
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    rows = _q(
        f"""SELECT pr.*, c.block, c.crop, c.area_ha, s.name as season_name
            FROM crop_production_records pr
            JOIN crops c ON pr.crop_block_id=c.id
            LEFT JOIN seasons s ON pr.season_id=s.id
            {where}
            ORDER BY pr.record_date DESC""",
        tuple(args)
    )
    return jsonify(_rows(rows))


@bp.route("/crops/production-records", methods=["POST"])
def create_crop_production_record():
    user, err, code = _role("owner", "manager", "field")
    if err:
        return err, code
    d = request.get_json() or {}
    if not d.get("crop_block_id"):
        return jsonify({"error": "crop_block_id is required"}), 400
    rid = _m(
        """INSERT INTO crop_production_records
           (crop_block_id,season_id,actual_yield_kg,estimated_yield_kg,revenue,
            seed_cost,fertiliser_cost,chemical_cost,irrigation_cost,labour_cost,
            fuel_cost,machinery_cost,harvest_cost,water_mm_applied,record_date,notes,created_by)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
        (d["crop_block_id"], d.get("season_id"),
         d.get("actual_yield_kg",0), d.get("estimated_yield_kg",0), d.get("revenue",0),
         d.get("seed_cost",0), d.get("fertiliser_cost",0), d.get("chemical_cost",0),
         d.get("irrigation_cost",0), d.get("labour_cost",0), d.get("fuel_cost",0),
         d.get("machinery_cost",0), d.get("harvest_cost",0), d.get("water_mm_applied",0),
         d.get("record_date", date.today().isoformat()), d.get("notes"), user["id"])
    )
    return jsonify(_row(_q("SELECT * FROM crop_production_records WHERE id=%s", (rid,), one=True))), 201


@bp.route("/crops/production-records/<int:rid>", methods=["PUT"])
def update_crop_production_record(rid):
    user, err, code = _role("owner", "manager", "field")
    if err:
        return err, code
    d = request.get_json() or {}
    _m(
        """UPDATE crop_production_records SET
           actual_yield_kg=%s, estimated_yield_kg=%s, revenue=%s,
           seed_cost=%s, fertiliser_cost=%s, chemical_cost=%s,
           irrigation_cost=%s, labour_cost=%s, fuel_cost=%s,
           machinery_cost=%s, harvest_cost=%s, water_mm_applied=%s,
           notes=%s WHERE id=%s""",
        (d.get("actual_yield_kg",0), d.get("estimated_yield_kg",0), d.get("revenue",0),
         d.get("seed_cost",0), d.get("fertiliser_cost",0), d.get("chemical_cost",0),
         d.get("irrigation_cost",0), d.get("labour_cost",0), d.get("fuel_cost",0),
         d.get("machinery_cost",0), d.get("harvest_cost",0), d.get("water_mm_applied",0),
         d.get("notes"), rid)
    )
    return jsonify(_row(_q("SELECT * FROM crop_production_records WHERE id=%s", (rid,), one=True)))


@bp.route("/crops/season-comparison", methods=["GET"])
def crop_season_comparison():
    """Multi-season yield/revenue trend per crop block."""
    user, err, code = _auth()
    if err:
        return err, code
    rows = _q("""
        SELECT c.block, c.crop, c.area_ha,
               s.name AS season_name, s.start_date,
               pr.actual_yield_kg, pr.revenue,
               (pr.seed_cost + pr.fertiliser_cost + pr.chemical_cost + pr.irrigation_cost +
                pr.labour_cost + pr.fuel_cost + pr.machinery_cost + pr.harvest_cost) AS total_cost
        FROM crop_production_records pr
        JOIN crops c ON pr.crop_block_id=c.id
        LEFT JOIN seasons s ON pr.season_id=s.id
        ORDER BY c.block, s.start_date
    """)
    return jsonify(_rows(rows))


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 9 — Labour Analytics
# ─────────────────────────────────────────────────────────────────────────────

@bp.route("/labour/analytics", methods=["GET"])
def labour_analytics():
    user, err, code = _auth()
    if err:
        return err, code

    # Actual hours from labor_allocations
    workers = _q("""
        SELECT w.id, w.name, w.role, w.department, w.salary,
               COALESCE(SUM(la.hours),0) AS actual_hours,
               COALESCE(SUM(la.hours * la.hourly_rate),0) AS allocated_cost
        FROM workers w
        LEFT JOIN labor_allocations la ON la.worker_id=w.id
        GROUP BY w.id, w.name, w.role, w.department, w.salary
        ORDER BY allocated_cost DESC
    """)

    # Planned hours
    plans = _q("SELECT worker_id, SUM(planned_hours) AS planned FROM labour_plans GROUP BY worker_id")
    plan_map = {p["worker_id"]: _float(p["planned"]) for p in _rows(plans)}

    # Total farm hectares
    ha_row = _q("SELECT COALESCE(SUM(area_ha),0) AS ha FROM operational_units WHERE active=TRUE", one=True)
    total_ha = _float(ha_row["ha"]) or 1

    # Total production value (revenue proxy for productivity)
    rev_row = _q("SELECT COALESCE(SUM(amount),0) AS t FROM finance WHERE type='income'", one=True)
    total_revenue = _float(rev_row["t"])

    result = []
    total_hours = 0.0
    total_cost = 0.0
    for w in _rows(workers):
        wid = w["id"]
        actual = _float(w["actual_hours"])
        planned = plan_map.get(wid, 0.0)
        cost = _float(w["allocated_cost"])
        salary = _float(w["salary"])
        total_hours += actual
        total_cost += cost

        w["planned_hours"] = planned
        w["hours_variance"] = round(actual - planned, 1)
        w["efficiency_pct"] = KPIEngine.planned_vs_actual_hours_pct(actual, planned) if planned else None
        w["total_people_cost"] = cost + salary * 12 / 52  # weekly salary share
        w["cost_per_worker"] = KPIEngine.cost_per_worker(w["total_people_cost"], 1)
        result.append(w)

    # Farm-level KPIs
    farm_kpis = {
        "total_actual_hours": round(total_hours, 1),
        "total_labour_cost": round(total_cost, 2),
        "labour_productivity": KPIEngine.labour_productivity(total_revenue, total_hours),
        "labour_cost_per_ha": KPIEngine.labour_cost_per_ha(total_cost, total_ha),
        "output_per_labour_hour": KPIEngine.output_per_labour_hour(total_revenue, total_hours),
        "payroll_efficiency": KPIEngine.payroll_efficiency(total_revenue, total_cost),
        "cost_per_worker": KPIEngine.cost_per_worker(total_cost, max(len(result), 1)),
    }
    return jsonify({"workers": result, "farm_kpis": farm_kpis})


@bp.route("/labour/plans", methods=["GET"])
def get_labour_plans():
    user, err, code = _auth()
    if err:
        return err, code
    season_id = request.args.get("season_id")
    if season_id:
        rows = _q(
            """SELECT lp.*, w.name as worker_name, u.name as unit_name
               FROM labour_plans lp
               JOIN workers w ON lp.worker_id=w.id
               LEFT JOIN operational_units u ON lp.unit_id=u.id
               WHERE lp.season_id=%s ORDER BY lp.plan_month""",
            (season_id,)
        )
    else:
        rows = _q("""
            SELECT lp.*, w.name as worker_name, u.name as unit_name
            FROM labour_plans lp
            JOIN workers w ON lp.worker_id=w.id
            LEFT JOIN operational_units u ON lp.unit_id=u.id
            ORDER BY lp.plan_month DESC
        """)
    return jsonify(_rows(rows))


@bp.route("/labour/plans", methods=["POST"])
def create_labour_plan():
    user, err, code = _role("owner", "manager")
    if err:
        return err, code
    d = request.get_json() or {}
    if not d.get("worker_id") or not d.get("plan_month"):
        return jsonify({"error": "worker_id and plan_month are required"}), 400
    pid = _m(
        """INSERT INTO labour_plans
           (worker_id,unit_id,season_id,plan_month,planned_hours,overtime_budget,notes)
           VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
        (d["worker_id"], d.get("unit_id"), d.get("season_id"),
         d["plan_month"], d.get("planned_hours",0), d.get("overtime_budget",0), d.get("notes"))
    )
    return jsonify(_row(_q("SELECT * FROM labour_plans WHERE id=%s", (pid,), one=True))), 201


@bp.route("/labour/overtime-report", methods=["GET"])
def labour_overtime_report():
    """Workers whose actual hours exceed their planned hours for a given month."""
    user, err, code = _auth()
    if err:
        return err, code
    month = request.args.get("month", date.today().strftime("%Y-%m"))

    rows = _q("""
        SELECT w.id, w.name, w.role,
               lp.planned_hours,
               lp.overtime_budget,
               COALESCE(SUM(la.hours),0) AS actual_hours
        FROM workers w
        JOIN labour_plans lp ON lp.worker_id=w.id AND lp.plan_month=%s
        LEFT JOIN labor_allocations la ON la.worker_id=w.id
            AND TO_CHAR(la.allocation_date,'YYYY-MM')=%s
        GROUP BY w.id, w.name, w.role, lp.planned_hours, lp.overtime_budget
        HAVING COALESCE(SUM(la.hours),0) > lp.planned_hours
        ORDER BY (COALESCE(SUM(la.hours),0) - lp.planned_hours) DESC
    """, (month, month))

    result = []
    for r in _rows(rows):
        r["overtime_hours"] = round(_float(r["actual_hours"]) - _float(r["planned_hours"]), 1)
        r["overtime_cost"] = round(r["overtime_hours"] * 1.5 * (_float(r["overtime_budget"]) / max(_float(r["planned_hours"]), 1)), 2)
        result.append(r)
    return jsonify(result)


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 10 — Asset Performance Management
# ─────────────────────────────────────────────────────────────────────────────

@bp.route("/assets/analytics", methods=["GET"])
def asset_analytics():
    user, err, code = _auth()
    if err:
        return err, code

    assets = _q("""
        SELECT a.id, a.asset_id, a.description, a.category, a.value,
               a.status, a.location,
               ad.annual_depreciation, ad.accumulated_depreciation,
               ad.useful_life_years, ad.method, ad.residual_value
        FROM assets a
        LEFT JOIN asset_depreciation ad ON ad.asset_id=a.id
        ORDER BY a.value DESC
    """)

    result = []
    for asset in _rows(assets):
        aid = asset["id"]
        cost = _float(asset["value"])
        accum_dep = _float(asset["accumulated_depreciation"])
        annual_dep = _float(asset["annual_depreciation"])

        # Usage
        usage = _q("""
            SELECT COALESCE(SUM(hours_used),0) AS total_hours,
                   COALESCE(SUM(km_travelled),0) AS total_km,
                   COALESCE(SUM(fuel_cost),0) AS total_fuel_cost,
                   COUNT(DISTINCT log_date) AS days_used
            FROM asset_usage_logs WHERE asset_id=%s
        """, (aid,), one=True)

        total_hours = _float(usage["total_hours"]) if usage else 0.0
        total_km = _float(usage["total_km"]) if usage else 0.0
        total_fuel = _float(usage["total_fuel_cost"]) if usage else 0.0
        days_used = int(usage["days_used"]) if usage else 0

        # Maintenance cost from finance records
        maint = _q(
            "SELECT COALESCE(SUM(amount),0) AS mc FROM finance WHERE type='expense' AND category='Maintenance' AND description ILIKE %s",
            (f"%{asset['asset_id']}%",), one=True
        )
        maint_cost = _float(maint["mc"]) if maint else 0.0

        total_operating_cost = total_fuel + maint_cost + accum_dep

        book_value = AssetCalculator.asset_book_value(cost, accum_dep)
        # ROI: assume asset generates revenue proportional to its cost share
        rev_row = _q("SELECT COALESCE(SUM(amount),0) AS t FROM finance WHERE type='income'", one=True)
        total_rev = _float(rev_row["t"])
        total_asset_val = _q("SELECT COALESCE(SUM(value),0) AS t FROM assets", one=True)
        asset_rev_share = total_rev * (cost / max(_float(total_asset_val["t"]), 1))

        net_income = asset_rev_share - total_operating_cost
        available_days = 365
        available_hours = available_days * 8  # 8h working day

        perf = {
            "book_value": round(book_value, 2),
            "total_hours_used": total_hours,
            "total_km": total_km,
            "total_fuel_cost": total_fuel,
            "total_maintenance_cost": maint_cost,
            "total_operating_cost": round(total_operating_cost, 2),
            "cost_per_hour": AssetCalculator.cost_per_hour(total_operating_cost, total_hours),
            "cost_per_km": round(_safe_div(total_operating_cost, total_km), 2) if total_km else None,
            "utilisation_pct": AssetCalculator.asset_utilisation_pct(total_hours, available_hours),
            "maintenance_cost_ratio_pct": AssetCalculator.maintenance_cost_ratio(maint_cost, cost),
            "asset_roi_pct": AssetCalculator.asset_roi(net_income, cost),
            "annual_depreciation": annual_dep,
            "accumulated_depreciation": accum_dep,
            "payback_period_years": FinanceCalculator.payback_period_years(cost, max(asset_rev_share - total_fuel - maint_cost, 1)),
            "efficiency_score": AssetCalculator.asset_efficiency_score(
                AssetCalculator.asset_utilisation_pct(total_hours, available_hours),
                AssetCalculator.asset_roi(net_income, cost),
                AssetCalculator.maintenance_cost_ratio(maint_cost, cost),
            ),
        }
        asset["performance"] = perf
        result.append(asset)

    return jsonify(result)


@bp.route("/assets/usage-logs", methods=["GET"])
def get_asset_usage_logs():
    user, err, code = _auth()
    if err:
        return err, code
    asset_id = request.args.get("asset_id")
    rows = _q(
        """SELECT aul.*, a.description as asset_desc, a.asset_id as asset_ref,
                  w.name as operator_name, u.name as unit_name
           FROM asset_usage_logs aul
           JOIN assets a ON aul.asset_id=a.id
           LEFT JOIN workers w ON aul.operator_id=w.id
           LEFT JOIN operational_units u ON aul.unit_id=u.id
           WHERE (%s IS NULL OR aul.asset_id=%s)
           ORDER BY aul.log_date DESC LIMIT 200""",
        (asset_id, asset_id)
    )
    return jsonify(_rows(rows))


@bp.route("/assets/usage-logs", methods=["POST"])
def create_asset_usage_log():
    user, err, code = _role("owner", "manager", "field")
    if err:
        return err, code
    d = request.get_json() or {}
    if not d.get("asset_id"):
        return jsonify({"error": "asset_id is required"}), 400
    lid = _m(
        """INSERT INTO asset_usage_logs
           (asset_id,log_date,hours_used,km_travelled,fuel_cost,operator_id,unit_id,notes)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
        (d["asset_id"], d.get("log_date", date.today().isoformat()),
         d.get("hours_used",0), d.get("km_travelled",0), d.get("fuel_cost",0),
         d.get("operator_id"), d.get("unit_id"), d.get("notes"))
    )
    return jsonify(_row(_q("SELECT * FROM asset_usage_logs WHERE id=%s", (lid,), one=True))), 201


@bp.route("/assets/usage-logs/<int:lid>", methods=["DELETE"])
def delete_asset_usage_log(lid):
    user, err, code = _role("owner", "manager")
    if err:
        return err, code
    _m("DELETE FROM asset_usage_logs WHERE id=%s", (lid,))
    return jsonify({"deleted": lid})


@bp.route("/assets/replacement-forecast", methods=["GET"])
def asset_replacement_forecast():
    """Assets approaching end of useful life within 2 years."""
    user, err, code = _auth()
    if err:
        return err, code
    rows = _q("""
        SELECT a.id, a.asset_id, a.description, a.value, a.category,
               ad.useful_life_years, ad.depreciation_start,
               ad.accumulated_depreciation, ad.residual_value,
               ad.annual_depreciation
        FROM assets a
        JOIN asset_depreciation ad ON ad.asset_id=a.id
        WHERE ad.depreciation_start IS NOT NULL
        ORDER BY ad.depreciation_start
    """)
    result = []
    for r in _rows(rows):
        if r["depreciation_start"]:
            start = r["depreciation_start"]
            if isinstance(start, str):
                start = datetime.strptime(start[:10], "%Y-%m-%d").date()
            years_elapsed = (date.today() - start).days / 365.25
            years_remaining = _float(r["useful_life_years"]) - years_elapsed
            r["years_elapsed"] = round(years_elapsed, 1)
            r["years_remaining"] = round(years_remaining, 1)
            r["replacement_due"] = years_remaining <= 2
            r["book_value"] = AssetCalculator.asset_book_value(_float(r["value"]), _float(r["accumulated_depreciation"]))
            result.append(r)

    result.sort(key=lambda x: x["years_remaining"])
    return jsonify(result)


# ─────────────────────────────────────────────────────────────────────────────
# CROSS-PHASE: Consolidated Enterprise KPI Dashboard
# ─────────────────────────────────────────────────────────────────────────────

@bp.route("/kpi-dashboard", methods=["GET"])
def enterprise_kpi_dashboard():
    """
    Single-endpoint enterprise KPI summary consumed by the frontend dashboard.
    Runs one CTE pass then computes all KPIs in Python using the CalculationEngine.
    """
    user, err, code = _auth()
    if err:
        return err, code

    agg = _q("""
        WITH
        fin  AS (SELECT
                    COALESCE(SUM(CASE WHEN type='income'  THEN amount ELSE 0 END),0) AS revenue,
                    COALESCE(SUM(CASE WHEN type='expense' THEN amount ELSE 0 END),0) AS expenses
                 FROM finance),
        cogs AS (SELECT COALESCE(SUM(amount),0) AS total FROM cogs_entries),
        act  AS (SELECT COALESCE(SUM(total_cost),0) AS total FROM operational_activities WHERE status='Completed'),
        lab  AS (SELECT COALESCE(SUM(hours*hourly_rate),0) AS cost,
                        COALESCE(SUM(hours),0) AS hours
                 FROM labor_allocations),
        dep  AS (SELECT COALESCE(SUM(annual_depreciation),0) AS total FROM asset_depreciation),
        inv  AS (SELECT COALESCE(SUM(on_hand*unit_cost),0) AS value,
                        COUNT(*) FILTER (WHERE on_hand <= par_level) AS low
                 FROM inventory),
        ls   AS (SELECT COALESCE(SUM(count),0) AS animals FROM livestock),
        cr   AS (SELECT COALESCE(SUM(area_ha),0) AS ha FROM crops),
        wk   AS (SELECT COUNT(*) AS total, COUNT(*) FILTER (WHERE status='Present') AS present FROM workers),
        au   AS (SELECT COALESCE(SUM(hours_used),0) AS hours FROM asset_usage_logs),
        ha   AS (SELECT COALESCE(SUM(area_ha),0) AS ha FROM operational_units WHERE active=TRUE)
        SELECT fin.revenue, fin.expenses, cogs.total AS cogs,
               act.total AS activity_costs, lab.cost AS labour_cost, lab.hours AS labour_hours,
               dep.total AS depreciation,
               inv.value AS inventory_value, inv.low AS low_stock,
               ls.animals, cr.ha AS crop_ha, wk.total AS workers, wk.present,
               au.hours AS asset_hours, ha.ha AS farm_ha
        FROM fin, cogs, act, lab, dep, inv, ls, cr, wk, au, ha
    """, one=True)

    if not agg:
        return jsonify({"error": "No data available"}), 200

    revenue = _float(agg["revenue"])
    cogs = _float(agg["cogs"])
    expenses = _float(agg["expenses"])
    activity_costs = _float(agg["activity_costs"])
    labour_cost = _float(agg["labour_cost"])
    labour_hours = _float(agg["labour_hours"])
    depreciation = _float(agg["depreciation"])
    farm_ha = _float(agg["farm_ha"]) or 1
    animals = int(_float(agg["animals"])) or 1
    workers = int(agg["workers"]) or 1
    asset_hours = _float(agg["asset_hours"])

    total_opex = expenses + activity_costs + labour_cost
    gross_profit = FinanceCalculator.gross_profit(revenue, cogs)
    operating_profit = FinanceCalculator.operating_profit(gross_profit, total_opex)
    ebitda_val = FinanceCalculator.ebitda(operating_profit, depreciation)

    return jsonify({
        # P&L summary
        "revenue": revenue,
        "cogs": cogs,
        "gross_profit": gross_profit,
        "gross_margin_pct": FinanceCalculator.gross_margin_pct(revenue, cogs),
        "operating_expenses": total_opex,
        "operating_profit": operating_profit,
        "ebitda": ebitda_val,
        "ebitda_margin_pct": ProfitabilityCalculator.ebitda_margin(ebitda_val, revenue),
        "net_profit": ebitda_val,  # simplified (no interest/tax model yet)
        "net_margin_pct": ProfitabilityCalculator.net_margin(ebitda_val, revenue),
        # Per-unit
        "profit_per_ha": CropCalculator.profit_per_ha(ebitda_val, farm_ha),
        "revenue_per_ha": CropCalculator.revenue_per_ha(revenue, farm_ha),
        "cost_per_ha": CropCalculator.cost_per_ha(total_opex, farm_ha),
        "profit_per_animal": LivestockCalculator.profit_per_head(ebitda_val, animals),
        "profit_per_worker": ProfitabilityCalculator.profit_per_worker(ebitda_val, workers),
        "labour_productivity": KPIEngine.labour_productivity(revenue, labour_hours),
        "labour_cost_per_ha": KPIEngine.labour_cost_per_ha(labour_cost, farm_ha),
        "payroll_efficiency": KPIEngine.payroll_efficiency(revenue, labour_cost),
        # Inventory
        "inventory_value": _float(agg["inventory_value"]),
        "low_stock_items": int(agg["low_stock"]),
        # Asset
        "total_asset_hours": asset_hours,
        # Operational
        "farm_ha": farm_ha,
        "total_animals": int(_float(agg["animals"])),
        "workers_present": int(agg["present"]),
        "workers_total": workers,
        # Calculation Engine health
        "registered_formulas": len(CalculationRegistry.all_formulas()),
    })


# ─────────────────────────────────────────────────────────────────────────────
# Registration
# ─────────────────────────────────────────────────────────────────────────────

def register_enterprise_routes(app: Flask, server_module):
    """
    Call this in server.py after all other routes:

        import erp_engine
        erp_engine.register_enterprise_routes(app, sys.modules[__name__])
    """
    global _server
    _server = server_module
    app.register_blueprint(bp)
    app_log_fn = getattr(server_module, "app_log", None)
    if app_log_fn:
        app_log_fn.info(
            "Enterprise ERP Engine registered",
            extra={
                "event": "ENTERPRISE_ENGINE_INIT",
                "routes": len(bp.deferred_functions),
                "formulas": len(CalculationRegistry.all_formulas()),
            }
        )
