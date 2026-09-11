"""Publish retained hosted work in an existing console campaign without calls."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from experiments.rig_web_app.storage import ConsoleDB
from experiments.rig_web_app.workspace_import import publish_hosted_program


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--hosted-program", type=Path, required=True)
    parser.add_argument("--input-plan", type=Path, required=True)
    parser.add_argument("--budget-root", type=Path, required=True)
    args = parser.parse_args(argv)

    def read(path):
        return json.loads(path.read_text(encoding="utf-8"))

    if not args.database.is_file():
        parser.error("Select an existing console database and campaign")
    db = ConsoleDB(args.database)
    try:
        result = publish_hosted_program(db, args.campaign_id,
            program=read(args.hosted_program), selections=read(args.input_plan)["selected"],
            budget_plan=read(args.budget_root / "plan.json"), ledger=read(args.budget_root / "ledger.json"),
            ledger_path=str((args.budget_root / "ledger.json").resolve()))
        print(json.dumps({"status": "published", "scope": "supplied hosted program only",
            "campaign_id": args.campaign_id, **result, "generation_calls": 0, "judge_calls": 0}))
    finally:
        db.close()


if __name__ == "__main__":
    main()
