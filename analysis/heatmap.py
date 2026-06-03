"""Activity heatmap generation."""

from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional


def _parse_iso(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def compute_heatmap(history: List[Dict]) -> List[Dict]:
    grid: Dict[int, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
    for h in history:
        ts = h.get("last_visit", "")
        if not ts:
            continue
        dt = _parse_iso(ts)
        if dt is not None:
            day = (dt.weekday() + 1) % 7
            grid[day][dt.hour] += 1

    return [
        {"day": day, "hour": hour, "count": grid[day][hour]}
        for day in range(7)
        for hour in range(24)
    ]
