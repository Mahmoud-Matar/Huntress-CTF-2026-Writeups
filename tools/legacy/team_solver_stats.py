#!/usr/bin/env python3
"""Display Huntress Game Master route completion and solver attribution.

Run on Kali, where /home/kali/token.txt is available, or set
HUNTRESS_GM_TOKEN in the environment. The token is never printed. Only
player-facing route names, modes, completion states, and solved_by names are
displayed; flags and raw Game Master responses are intentionally omitted.

Examples:
    python3 team_solver_stats.py
    python3 team_solver_stats.py --day 24
    python3 team_solver_stats.py --token-file /secure/path/token.txt
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from typing import Any

import requests


GAME_MASTER = "https://2026.huntress.ctf.games/"
MODE_LABELS = {
    "single_solve": "SS",
    "time_trial": "TT",
    "mastery": "M",
}
MODE_ORDER = tuple(MODE_LABELS)


def load_token(token_file: Path) -> str:
    """Read a bearer from the environment or a plain-text/JSON token file."""
    env_token = os.environ.get("HUNTRESS_GM_TOKEN", "").strip()
    if env_token:
        return env_token

    try:
        raw = token_file.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ValueError(
            "No token found. Set HUNTRESS_GM_TOKEN or provide a readable --token-file."
        ) from exc

    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        value = raw

    if isinstance(value, dict):
        token = value.get("token")
        if not isinstance(token, str) or not token.strip():
            raise ValueError("The JSON token file has no non-empty 'token' field.")
        expiry = value.get("expires_at")
        if expiry:
            print(f"Token expiry metadata: {expiry}", file=sys.stderr)
        return token.strip()

    if isinstance(value, str) and value.strip():
        return value.strip()
    raise ValueError("The token file is empty or has an unsupported format.")


def get_challenges(day: int | None, token: str) -> list[dict[str, Any]]:
    params: dict[str, int | str] = {"op": "list"}
    if day is not None:
        params["day"] = day
    response = requests.get(
        GAME_MASTER,
        params=params,
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
    )
    response.raise_for_status()
    body = response.json()
    challenges = body.get("challenges") if isinstance(body, dict) else None
    if not isinstance(challenges, list):
        raise ValueError("Game Master list response did not contain a challenges array.")
    return challenges


def get_status(route: dict[str, Any], token: str) -> dict[str, Any]:
    """Return a small safe projection, never the raw response or flag."""
    challenge_id = route.get("id")
    if not isinstance(challenge_id, str):
        return {"route": route, "error": "route has no challenge ID"}

    try:
        response = requests.get(
            GAME_MASTER,
            params={"op": "status", "challenge": challenge_id},
            headers={"Authorization": f"Bearer {token}"},
            timeout=25,
        )
    except requests.RequestException as exc:
        return {"route": route, "error": type(exc).__name__}

    if response.status_code == 409:
        return {"route": route, "result": "start_required", "status": None}
    if response.status_code != 200:
        return {"route": route, "error": f"HTTP {response.status_code}"}

    try:
        body = response.json()
    except ValueError:
        return {"route": route, "error": "non-JSON status response"}
    if not isinstance(body, dict):
        return {"route": route, "error": "status response was not an object"}

    solved_by = body.get("solved_by")
    solver = solved_by.get("name") if isinstance(solved_by, dict) else None
    return {
        "route": route,
        "result": body.get("result"),
        "status": body.get("status"),
        "solver": solver if isinstance(solver, str) and solver else None,
        "completed": body.get("result") == "CORRECT" and body.get("status") != "pending",
        "scoring_pending": body.get("result") == "CORRECT" and body.get("status") == "pending",
    }


def route_title(route: dict[str, Any]) -> tuple[Any, str]:
    return route.get("day"), str(route.get("name") or route.get("id") or "(untitled route)")


def print_report(challenges: list[dict[str, Any]], statuses: list[dict[str, Any]]) -> None:
    completed = [item for item in statuses if item.get("completed")]
    pending = [item for item in statuses if item.get("scoring_pending")]
    failures = [item for item in statuses if item.get("error")]
    unfinished = [
        item for item in statuses
        if not item.get("completed") and not item.get("scoring_pending") and not item.get("error")
    ]

    groups: dict[str, dict[tuple[Any, str], list[str]]] = {}
    for item in statuses:
        if not item.get("completed"):
            continue
        route = item["route"]
        solver = item.get("solver") or "(unknown)"
        title_key = route_title(route)
        modes = groups.setdefault(solver, {}).setdefault(title_key, [])
        mode = route.get("mode")
        if isinstance(mode, str) and mode not in modes:
            modes.append(mode)

    route_counts = {
        solver: sum(len(modes) for modes in titles.values())
        for solver, titles in groups.items()
    }
    print(f"Huntress CTF team solver report — {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}")
    print(
        f"Listed routes: {len(challenges)} | confirmed CORRECT: {len(completed)} | "
        f"scoring pending: {len(pending)} | status errors: {len(failures)}"
    )
    if groups:
        print("\nRecorded solver totals (route/mode entries):")
        for solver in sorted(groups, key=lambda name: (name == "(unknown)", name.casefold())):
            count = route_counts[solver]
            pct = (count / len(completed) * 100) if completed else 0
            print(f"  {solver}: {count} ({len(groups[solver])} challenge titles, {pct:.1f}%)")
        print("\nRoutes by recorded solver — SS=Single Solve, TT=Time Trial, M=Mastery:")
        for solver in sorted(groups, key=lambda name: (name == "(unknown)", name.casefold())):
            print(f"\n[{solver}]")
            titles = groups[solver]
            for (day, name), modes in sorted(
                titles.items(), key=lambda item: (item[0][0] or 0, item[0][1].casefold())
            ):
                mode_text = "/".join(
                    MODE_LABELS[mode] for mode in MODE_ORDER if mode in modes
                )
                print(f"  Day {day}: {name} ({mode_text})")
        if "(unknown)" in groups:
            print("\nNote: '(unknown)' means the Game Master could not verify who first solved the route.")

    if pending:
        print("\nScoring pending:")
        for item in pending:
            day, name = route_title(item["route"])
            print(f"  Day {day}: {name} ({item['route'].get('mode')})")

    if unfinished:
        print("\nNot confirmed CORRECT:")
        for item in unfinished:
            route = item["route"]
            day, name = route_title(route)
            print(f"  Day {day}: {name} ({route.get('mode')}) — {item.get('result') or 'unknown'}")

    if failures:
        print(f"\nStatus checks failed for {len(failures)} route(s):")
        for item in failures:
            route = item["route"]
            day, name = route_title(route)
            print(f"  Day {day}: {name} ({route.get('mode')}) — {item['error']}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--day", type=int, help="Limit the report to one day.")
    parser.add_argument(
        "--token-file",
        type=Path,
        default=Path("/home/kali/token.txt"),
        help="Token file (plain token or JSON with a 'token' field; default: /home/kali/token.txt).",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=8,
        help="Concurrent read-only status checks (default: 8).",
    )
    args = parser.parse_args()
    if args.workers < 1 or args.workers > 32:
        parser.error("--workers must be between 1 and 32")

    try:
        token = load_token(args.token_file)
        challenges = get_challenges(args.day, token)
    except (ValueError, requests.RequestException) as exc:
        print(f"Could not load the Game Master list: {exc}", file=sys.stderr)
        return 1

    statuses: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(get_status, route, token) for route in challenges]
        for future in as_completed(futures):
            statuses.append(future.result())

    # Restore API order for readable output.
    order = {route.get("id"): index for index, route in enumerate(challenges)}
    statuses.sort(key=lambda item: order.get(item.get("route", {}).get("id"), len(order)))
    print_report(challenges, statuses)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
