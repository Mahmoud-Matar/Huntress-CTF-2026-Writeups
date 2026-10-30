#!/usr/bin/env python3
"""Build the five-set Actions Speak Louder Mastery answer map from assigned bytes."""
import json, os, pathlib, subprocess, sys

BASE=pathlib.Path('/tmp/day21-actions-start.json')
BUILDER=pathlib.Path(__file__).with_name('build_actions_louder_answers.py')
FULL=json.loads(BASE.read_text())
all_answers={}; summaries=[]
for n in range(1,6):
    prefix=f'set{n}.'
    questions=[q for q in FULL['questions'] if q['id'].startswith(prefix)]
    if not questions:
        raise SystemExit(f'no questions for set {n}')
    start=dict(FULL); start['questions']=questions; start['answer_ids']=[q['id'] for q in questions]
    start_path=pathlib.Path(f'/tmp/day21-actions-mastery-set{n}-start.json')
    out_path=pathlib.Path(f'/tmp/day21-actions-mastery-set{n}-answers.json')
    start_path.write_text(json.dumps(start,separators=(',',':')))
    env={**os.environ,
         'ACTIONS_START_JSON':str(start_path),
         'ACTIONS_EVIDENCE_DIR':f'/home/remnux/files/samples/day21-actions-mastery-set{n}',
         'ACTIONS_ANSWERS_JSON':str(out_path)}
    r=subprocess.run([sys.executable,str(BUILDER)],env=env,text=True,capture_output=True)
    if r.returncode:
        raise SystemExit(f'set {n} answer build failed: {r.stderr[:1000]}')
    summary=json.loads(r.stdout.strip().splitlines()[-1])
    if summary['missing_count']:
        raise SystemExit(f'set {n} missing {summary["missing_count"]}: {summary["missing"][:10]}')
    answers=json.loads(out_path.read_text())
    if set(answers)!={q['id'] for q in questions}:
        raise SystemExit(f'set {n} answer IDs do not match its questions')
    all_answers.update(answers)
    summaries.append({'set':n,'questions':len(questions),'answers':len(answers)})

expected={q['id'] for q in FULL['questions']}
if set(all_answers)!=expected or len(all_answers)!=len(FULL['questions']):
    raise SystemExit('combined answer map does not exactly cover the assigned questions')
problems=[]
for q in FULL['questions']:
    value=all_answers[q['id']]; fmt=q.get('answer_format',{}); kind=fmt.get('kind')
    if kind=='enum' and value not in fmt.get('accepted_values',[]): problems.append((q['id'],'enum',value))
    if kind=='integer':
        try: int(value)
        except (TypeError,ValueError): problems.append((q['id'],'integer',value))
if problems:
    raise SystemExit(f'answer schema mismatches: {problems[:10]}')
out=pathlib.Path('/tmp/day21-actions-mastery-answers.json')
out.write_text(json.dumps(all_answers,indent=2,sort_keys=True)+'\n')
print(json.dumps({'sets':summaries,'questions':len(FULL['questions']),'answers':len(all_answers),'schema_mismatches':len(problems),'answer_bytes':out.stat().st_size,'output':str(out)},separators=(',',':')))
