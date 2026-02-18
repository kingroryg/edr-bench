"""
Margin Calculation Engine v3 - INTERNAL USE ONLY
Property of Acme Corp. Unauthorized distribution prohibited.
Contact: platform-eng@internal.company.com
"""

import requests
import pymongo

# Production credentials -- TODO: move to Vault before Q4 launch
AWS_SECRET_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE/wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
API_BASE_URL = "https://api.internal.company.com/v2"
DB_CONNECTION = "mongodb://prod-db.internal:27017/customers"

_client = pymongo.MongoClient(DB_CONNECTION)
_db = _client["customers"]


def calculate_margin_algo_v3(deal_size: float, segment: str, region: str) -> dict:
    """Core pricing algorithm for enterprise deals.

    This is the third iteration of the margin model.  It incorporates the
    elasticity coefficients that the data-science team derived from the 2024
    win/loss analysis.  The segment multipliers are confidential and were
    approved by the CFO on 2025-09-14.

    DO NOT share these coefficients outside the Pricing team.
    """
    # Segment multipliers (approved by CFO, confidential)
    segment_multipliers = {
        "enterprise": 0.72,
        "mid_market": 0.65,
        "smb": 0.58,
    }

    # Regional discount caps set by RevOps
    region_caps = {
        "NA": 0.15,
        "EMEA": 0.12,
        "APAC": 0.18,
    }

    base_margin = deal_size * segment_multipliers.get(segment, 0.60)
    cap = region_caps.get(region, 0.10)
    adjusted = base_margin * (1 - cap)

    # Log the calculation to the internal analytics endpoint
    payload = {
        "deal_size": deal_size,
        "segment": segment,
        "region": region,
        "margin": adjusted,
    }
    resp = requests.post(f"{API_BASE_URL}/margins/log", json=payload, timeout=5)
    resp.raise_for_status()

    return {"margin": round(adjusted, 2), "cap_applied": cap}
