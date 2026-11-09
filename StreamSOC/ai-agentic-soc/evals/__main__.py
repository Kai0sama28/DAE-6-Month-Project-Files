"""Generate and store the labeled evaluation dataset.

Usage::

    python -m evals                         # JSONL + PostgreSQL
    python -m evals --no-db                 # JSONL only
    python -m evals --out /tmp/eval.jsonl   # custom output path
    python -m evals --check                 # validate only, write nothing
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from evals.generator import (
    DEFAULT_DATASET_ID,
    DEFAULT_SEED,
    generate_dataset,
    validate_dataset,
)
from evals.store import (
    DEFAULT_EVAL_DATABASE_URL,
    create_eval_engine,
    load_cases,
    write_jsonl,
)

DEFAULT_OUTPUT = Path(__file__).resolve().parent / "dataset" / f"{DEFAULT_DATASET_ID}.jsonl"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="evals",
        description="Generate the 50-case labeled evaluation dataset",
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUTPUT,
                        help=f"JSONL output path (default: {DEFAULT_OUTPUT})")
    parser.add_argument("--dataset-id", default=DEFAULT_DATASET_ID,
                        help=f"dataset identifier (default: {DEFAULT_DATASET_ID})")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED,
                        help=f"generation seed (default: {DEFAULT_SEED})")
    parser.add_argument("--database-url", default=DEFAULT_EVAL_DATABASE_URL,
                        help="PostgreSQL URL (default: EVAL_DATABASE_URL or local soc_triage_db)")
    parser.add_argument("--no-db", action="store_true",
                        help="write JSONL only; do not touch PostgreSQL")
    parser.add_argument("--check", action="store_true",
                        help="validate the generated dataset and exit without writing")
    args = parser.parse_args(argv)

    cases = generate_dataset(seed=args.seed, dataset_id=args.dataset_id)
    summary = validate_dataset(cases)

    print(f"dataset:  {summary['dataset_id']}")
    print(f"cases:    {summary['case_count']} ({summary['malicious']} malicious, "
          f"{summary['benign']} benign)")
    print(f"alerts:   {summary['alert_count']}")
    for label, count in summary["label_counts"].items():
        print(f"  {label:<22} {count}")

    if args.check:
        print("validation: OK (nothing written)")
        return 0

    output = write_jsonl(cases, args.out)
    print(f"jsonl:    {output}")

    if not args.no_db:
        try:
            engine = create_eval_engine(args.database_url)
            counts = load_cases(
                cases,
                engine=engine,
                dataset_id=args.dataset_id,
                seed=args.seed,
                split="test",
            )
            print(f"postgres: {counts['cases']} cases / {counts['alerts']} alerts "
                  f"in schema eval")
        except Exception as exc:
            print(f"postgres: FAILED — {exc}", file=sys.stderr)
            print("  (the JSONL file was still written; rerun with --no-db to skip)",
                  file=sys.stderr)
            return 1

    print("validation: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
