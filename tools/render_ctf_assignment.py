import json,pathlib,sys
p=pathlib.Path(sys.argv[1]);r=json.loads(p.read_text());out=p.with_suffix('.md');s=['# '+r['name'],'',r['prompt'],'','## Attempt and timer','']
for k,v in r.items():
 if k not in ('questions','guidance','artifacts','answer_ids','downloads','download','sha256','name','prompt'):s+=['**'+k+'**: '+json.dumps(v,ensure_ascii=False),'']
s+=['## Files','']
for i,a in enumerate(r['artifacts'],1):
 f=pathlib.Path(sys.argv[2].format(i=i)).resolve();s+=['['+a.get('filename',f.name)+']('+str(f)+')','', 'SHA-256: `'+a['sha256']+'`','', 'Authenticated direct route: `https://2026.huntress.ctf.games/'+a['download']+'`','']
s+=['## Questions and answer formats','']
for i,q in enumerate(r['questions'],1):
 s+=[f"### {i}. `{q['id']}`",'',q['question'],'']
 for k,v in q.items():
  if k not in ('id','question'):s+=['**'+k+'**: '+json.dumps(v,ensure_ascii=False),'']
s+=['## Guidance','',r['guidance'],'','## Completion','','Submit every finding under its exact answer ID through the authenticated Game Master. Done requires CORRECT and confirmed scoring.']
out.write_text('\n'.join(s)+'\n');print(out)
