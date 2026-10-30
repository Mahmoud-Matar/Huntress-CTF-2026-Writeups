#!/usr/bin/env python3
"""Build the five set-qualified answer maps for Resourceful Mastery."""
from __future__ import annotations

import json, pathlib, shutil, subprocess, sys

ROOT=pathlib.Path(__file__).resolve().parents[1]
DATA=ROOT/'challenges'/'data'
ORIGINAL=pathlib.Path('/tmp/flowstate-tt-start.json')
FULL=pathlib.Path('/tmp/resourceful-mastery-full-start.json')
STAGED=pathlib.Path('/tmp/resourceful-mastery-set-start.json')
STAGED_ARCHIVE=pathlib.Path('/tmp/resourceful-mastery-set-evidence.zip')
SOLVER_OUTPUT=DATA/'resourceful-day20-answers.json'
OUTPUT=DATA/'resourceful-day20-mastery-answers.json'
SOLVER=ROOT/'tools/solve_resourceful_day20.py'

def main():
    if not FULL.exists(): shutil.copyfile(ORIGINAL,FULL)
    original=json.loads(FULL.read_text())
    artifacts=original['artifacts']
    if len(artifacts)!=5: raise SystemExit('expected five mastery artifacts')
    combined={}
    for n,artifact in enumerate(artifacts,1):
        archive=pathlib.Path(f'/tmp/jack-mastery-{n}.zip')
        if not archive.exists(): raise SystemExit(f'missing delivery {n}')
        subset=[q for q in original['questions'] if q.get('set')==n]
        if len(subset)!=240: raise SystemExit(f'delivery {n} has {len(subset)} questions, expected 240')
        staged=dict(original)
        staged['sha256']=artifact['sha256']
        staged['questions']=[]
        for q in subset:
            q=dict(q)
            prefix=f'set{n}.'
            if not q['id'].startswith(prefix): raise SystemExit(f'unexpected answer ID {q["id"]}')
            q['id']=q['id'][len(prefix):]
            staged['questions'].append(q)
        staged['answer_ids']=[q['id'] for q in staged['questions']]
        STAGED.write_text(json.dumps(staged))
        shutil.copyfile(archive,STAGED_ARCHIVE)
        # The parser reads fixed paths in /tmp for the active staged delivery.
        shutil.copyfile(STAGED,ORIGINAL)
        shutil.copyfile(STAGED_ARCHIVE,pathlib.Path('/tmp/flowstate-tt-evidence.zip'))
        proc=subprocess.run([sys.executable,str(SOLVER)],capture_output=True,text=True)
        if proc.returncode:
            raise SystemExit(f'delivery {n} parser failed:\n{proc.stdout}\n{proc.stderr}')
        parsed=json.loads(SOLVER_OUTPUT.read_text())
        expected=set(q['id'] for q in staged['questions'])
        if set(parsed)!=expected:
            raise SystemExit(f'delivery {n}: parsed {len(parsed)}/{len(expected)} fields')
        combined.update({f'set{n}.{k}':v for k,v in parsed.items()})
        print(f'delivery {n}: {len(parsed)} answers; {artifact["sha256"]}')
    # Restore the full assignment and verify the combined map against it.
    ORIGINAL.write_text(FULL.read_text())
    full=json.loads(ORIGINAL.read_text())
    expected=set(full['answer_ids'])
    if set(combined)!=expected:
        raise SystemExit(f'combined answer IDs differ: {len(combined)}/{len(expected)}')
    OUTPUT.write_text(json.dumps(combined,indent=2,sort_keys=True)+'\n')
    print(f'combined: {len(combined)} exact answers -> {OUTPUT}')

if __name__=='__main__': main()
