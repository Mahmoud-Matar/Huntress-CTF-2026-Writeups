import json,pathlib,subprocess
from solve_crash_course import solve
p=pathlib.Path(__file__).resolve().parents[1]/'challenges'/'data'/'crash-course-mastery';r=json.loads((p/'start.json').read_text());allanswers={}
for i in range(1,len(r['artifacts'])+1):
 d=p/f'set{i}';qs=[]
 for q in r['questions']:
  if q['id'].startswith(f'set{i}.'):
   q=dict(q);q['id']=q['id'].split('.',1)[1];qs.append(q)
 assert len(qs)==312
 (d/'start.json').write_text(json.dumps({'questions':qs}))
 subprocess.run(['7z','x','-y','-pinfected','-o'+str(d/'files'),str(d/'evidence.zip')],stdout=subprocess.DEVNULL,check=True)
 a,m=solve(d/'start.json',d/'evidence.zip',d/'files',d/'answers.json');assert not m
 allanswers.update({f'set{i}.'+k:str(v) for k,v in a.items()});print('completed set',i,flush=True)
assert set(allanswers)==set(r['answer_ids']);(p/'answers.json').write_text(json.dumps(allanswers));print('all answers',len(allanswers),flush=True)
