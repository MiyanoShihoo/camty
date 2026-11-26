#!/usr/bin/env python3
"""Non-overwriting local scaffolder. Dry-run unless --apply is specified."""
from __future__ import annotations
import argparse
from pathlib import Path
import shutil

MAP = {
    'AUTONOMY_TEMPLATE.md': 'AUTONOMY.md',
    'STATE_TEMPLATE.md': 'STATE.md',
    'PLAN_TEMPLATE.md': 'PLAN.md',
    'DECISIONS_TEMPLATE.md': 'DECISIONS.md',
    'REVIEW_LEDGER_TEMPLATE.md': 'REVIEW_LEDGER.md',
    'SDS_TEMPLATE.md': 'SDS.md',
    'IMPLEMENTATION_PLAN_TEMPLATE.md': 'IMPLEMENTATION_PLAN.md',
    'TASKS_TEMPLATE.md': 'TASKS.md',
    'HANDOFF_TEMPLATE.md': 'HANDOFF.md',
}

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', required=True, help='Existing repository/project directory')
    parser.add_argument('--destination', default='docs/agent-orchestrator', help='Relative path INSIDE project')
    parser.add_argument('--apply', action='store_true', help='Write absent files; no overwrites')
    args = parser.parse_args()
    root = Path(args.project).expanduser().resolve()
    if not root.is_dir():
        parser.error('--project must point to an existing directory')
    dest_arg = Path(args.destination)
    if dest_arg.is_absolute() or '..' in dest_arg.parts:
        parser.error('--destination must be a safe relative path')
    target = (root / dest_arg).resolve()
    if not target.is_relative_to(root):
        parser.error('--destination resolves outside project')
    srcdir = Path(__file__).resolve().parent.parent / 'assets'
    for source, destname in MAP.items():
        original = srcdir / source
        new = target / destname
        if new.exists():
            print(f'SKIP existing: {new}')
        else:
            print(f'{"CREATE" if args.apply else "WOULD CREATE"}: {new}')
            if args.apply:
                target.mkdir(parents=True, exist_ok=True)
                # Fail closed if concurrent creation happened.
                with new.open('x', encoding='utf-8') as out:
                    out.write(original.read_text(encoding='utf-8'))
    if not args.apply:
        print('\nDry-run only. Add --apply to create missing files.')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
