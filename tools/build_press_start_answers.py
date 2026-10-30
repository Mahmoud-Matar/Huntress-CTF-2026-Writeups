#!/usr/bin/env python3
"""Build Day 23 Press Start answers from its assigned files, statically."""
import json, os, pathlib, re, sys
from urllib.parse import urlsplit
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import solve_fetch_quest_day17 as solver

START = pathlib.Path(os.environ.get('PRESS_START_START', '/tmp/day23-press-start-single.json'))
ROOT = pathlib.Path(os.environ.get('PRESS_START_ROOT', '/tmp/day23-press-start/files'))
OUT = pathlib.Path(os.environ.get('PRESS_START_OUT', '/tmp/day23-press-start-answers.json'))

def graph_role(steps):
    s = steps.replace(',', '>')
    if s == 'decode_configuration>return_configuration': return 'benign_utility'
    if 'dispatch_next_stage' in s: return 'relay'
    if 'handoff_script' in s: return 'staged_chain'
    if 'profile_host' in s and 'acquire_remote' in s and 'write_file' in s and 'dispatch_process' in s: return 'staged_chain'
    if 'acquire_remote' in s and 'write_file' in s and 'dispatch_process' in s: return 'staged_chain'
    if 'build_schedule' in s and 'register_descriptor' in s: return 'persistence_descriptor'
    if 'transform_content' in s or 'transform_copy' in s: return 'impact'
    if 'upload_remote' in s or 'transmit_remote' in s: return 'uploader'
    if 'locate_local' in s and 'dispatch_process' in s: return 'launcher'
    if 'acquire_remote' in s and ('dispatch_memory' in s or 'dispatch_pipe' in s): return 'stager'
    if 'decode_embedded' in s and 'write_file' in s: return 'dropper'
    if 'acquire_remote' in s and 'write_file' in s: return 'downloader'
    return 'unknown'

def attack_for(fields, prefix):
    if fields.get('attack'): return fields['attack']
    s=fields.get('steps','').replace(',','>')
    language_id={'jscript':'T1059.007','nodejs':'T1059.007','batch':'T1059.003','vbscript':'T1059.005','python':'T1059.006'}
    interpreter=language_id.get(prefix,'T1059')
    # In this corpus the Node/Python specimens that explicitly terminate in a
    # process dispatch record their interpreter technique as the primary ID.
    if prefix in ('nodejs','python') and 'dispatch_process' in s: return interpreter
    if 'handoff_script' in s or 'dispatch_next_stage' in s: return interpreter
    if s=='decode_configuration>return_configuration': return 'none'
    if 'acquire_remote' in s: return 'T1105'
    if 'decode_embedded' in s: return 'T1140'
    if 'upload_remote' in s or 'transmit_remote' in s: return 'T1041'
    if 'dispatch_process' in s: return interpreter
    if 'build_schedule' in s and 'register_descriptor' in s:
        return 'T1053.003' if '/cron.d/' in fields.get('schedule_path','') else 'T1053.005'
    if 'transform_content' in s or 'transform_copy' in s: return 'T1486'
    return fields.get('attack')

def code_styles(text):
    m = re.search(r'(?im)^\s*(?:var\s+)?(inspect_[A-Za-z0-9_]+)\s*=\s*function(?:\s+([A-Za-z0-9_]+))?\s*\(', text)
    if not m:
        fs = 'declaration' if re.search(r'(?m)^\s*function\s+inspect_', text) else 'anonymous_expression'
    else: fs = 'named_expression' if m.group(2) else 'anonymous_expression'
    inv = 'apply' if re.search(r'recover_[A-Za-z0-9_]+\.apply\s*\(', text) else 'call' if re.search(r'recover_[A-Za-z0-9_]+\.call\s*\(', text) else 'direct'
    im = re.search(r'(?is)(?:function\s+inspect_[^(]+\([^)]*\)|inspect_[A-Za-z0-9_]+\s*=\s*function[^\{]*\{)(.*?)(?:\n\s*};?|\n\s*})', text)
    body = im.group(1) if im else ''
    vm = re.search(r'(?:var|let|const)\s+([A-Za-z_][\w]*)\s*=\s*eval\s*\(', body)
    if not vm: return fs, inv, 'unknown'
    props = re.findall(re.escape(vm.group(1)) + r'(?:\.([A-Za-z_$][\w$]*)|\[[\'\"]([^\'\"]+)[\'\"]\])', body[vm.start():])
    kinds = {'bracket_literal' if b else 'dot' for a,b in props}
    return fs, inv, next(iter(kinds)) if len(kinds)==1 else 'mixed' if kinds else 'unknown'

def primary_indicator(f):
    for key in ('url','upload_url','next_stage','file_path','schedule_path','recovery_note','note_name','host_id'):
        if f.get(key): return f[key]
    return None

def batch_control(text):
    if re.search(r'(?im)^\s*if\s+errorlevel\s+\d+\s+',text): return 'errorlevel_guard'
    if re.search(r'(?im)^\s*if\s+(?:defined\s+\w+|\w+.*?)\s+(?:set|call)\b',text): return 'if_guard'
    # A labeled CALL remains the wrapper even when nested in a one-shot FOR.
    if re.search(r'(?im)^.*\bcall\s+:HUNTRESS_RECOVER\b',text): return 'call_subroutine'
    if re.search(r'(?im)^\s*goto\s+:HUNTRESS_DISPATCH\s*$',text): return 'goto_dispatch'
    if re.search(r'(?im)^\s*for\s+/l\s+%%\w+\s+in\s*\(\s*1\s*,\s*1\s*,\s*1\s*\)\s+do\s+call\s+:',text): return 'for_once'
    if re.search(r'(?im)^\s*for\s+%%\w+.*\bdo\s+call\s+set\b',text): return 'direct'
    return 'direct'

def batch_expansion(text):
    lines=text.splitlines()
    if re.search(r'(?im)^\s*for\s+%%\w+.*\bdo\s+call\s+set\s+.*=%%[^%]+%%[^%]*%%',text):
        return 'for_indirect'
    for i,line in enumerate(lines):
        if re.search(r'(?i)\b(?:cfg|item\d+|recovered|recovered_configuration)\s*=',line) and any(x in line for x in ('%','!')):
            if '!' in line: return 'delayed'
            if re.search(r'(?i)\bcall\s+set\b',line): return 'call_double'
            return 'percent'
    return 'percent'

def vb_control(text):
    if re.search(r'(?im)^\s*For\s+\w+\s*=\s*\d+\s+To\s+\d+',text): return 'for_once'
    if re.search(r'(?im)^\s*Do\s*$',text) and re.search(r'(?im)^\s*Exit\s+Do',text): return 'do_once'
    if re.search(r'(?im)^\s*While\s+',text): return 'while_once'
    if re.search(r'(?im)^\s*Select\s+Case\s+',text): return 'select_case'
    if re.search(r'(?im)On Error Resume Next',text): return 'error_guard'
    return 'direct'

def value_for(q, fields, source, filename):
    aid=re.sub(r'^set\d+\.', '', q['id'].lower()); suffix=aid.split('-')[-1]; prefix=aid.split('-',1)[0]
    if prefix=='powershell':
        c=fields.get('c',''); b=fields.get('b','')
        scenario='impact' if b.startswith('.') else 'collection' if 'Login Data' in c or 'Cookies' in c else 'resource'
        url=fields.get('d') if scenario=='impact' else b
        secondary=fields.get('c','').split('>')[0] if scenario=='collection' else fields.get('c')
        vals=list(fields.values())
        mutex=next((v for v in vals if v.startswith('Global\\')),None)
        user_agent=next((v for v in vals if v.startswith('Mozilla/')),None)
        extension=next((v for v in vals if v.startswith('.')),None)
        tertiary=user_agent if scenario=='collection' else extension if scenario=='impact' else mutex
        return {'url':url,'secondary':secondary,'tertiary':tertiary}.get(suffix)
    if prefix=='jscript':
        if suffix=='role': return graph_role(fields.get('steps',''))
        if suffix=='attack': return attack_for(fields,prefix)
        if suffix=='style': return '|'.join(code_styles(source))
        if suffix=='campaign': return fields.get('campaign_id')
        if suffix=='steps': return fields.get('steps','').replace(',','>')
        if suffix=='token': return fields.get('campaign_id','').split('-',1)[1] if '-' in fields.get('campaign_id','') else None
        if suffix=='indicator': return primary_indicator(fields)
    if prefix=='batch':
        if suffix=='role': return graph_role(fields.get('steps',''))
        if suffix=='attack': return attack_for(fields,prefix)
        if suffix=='style': return '|'.join((fields.get('graph',''),batch_control(source),batch_expansion(source)))
        if suffix=='campaign': return fields.get('campaign_id')
        if suffix=='steps': return fields.get('steps','').replace(',','>')
        if suffix=='token': return fields.get('campaign_id','').split('-',1)[1] if '-' in fields.get('campaign_id','') else None
        if suffix=='indicator': return primary_indicator(fields)
    if prefix=='vbscript':
        if suffix=='role': return graph_role(fields.get('steps',''))
        if suffix=='attack': return attack_for(fields,prefix)
        if suffix=='style':
            cm=re.search(r'(?im)^\s*Const\s+Codec_[A-Za-z0-9_]+\s*=\s*"([^"]+)"',source)
            parts=cm.group(1).split('|') if cm else ['identity','identity']
            return '|'.join((parts[0],parts[1] if len(parts)>1 else 'identity',vb_control(source)))
        if suffix=='campaign': return fields.get('campaign_id')
        if suffix=='steps': return fields.get('steps','').replace(',','>')
        if suffix=='token': return fields.get('campaign_id','').split('-',1)[1] if '-' in fields.get('campaign_id','') else None
        if suffix=='indicator': return primary_indicator(fields)
    if prefix=='python':
        if suffix=='role': return graph_role(fields.get('steps',''))
        if suffix=='attack': return attack_for(fields,prefix)
        if suffix=='carrier': return '|'.join((fields.get('carrier',''),fields.get('windows_chain','')))
        if suffix=='obfuscation': return '|'.join((fields.get('syntax',''),fields.get('obfuscation','')))
        if aid.endswith('-handoff-id'):
            # The Python handoff id is supplied by its paired PowerShell precursor.
            archive=q['artifact'].split('->')[0].strip()
            mset=re.search(r'evidence-(\d+)\.zip$',archive)
            precursor=(pathlib.Path(ROOT)/mset.group(1)/'e119e7.ps1') if mset else (pathlib.Path(ROOT)/'e119e7.ps1')
            if precursor.exists():
                try: return solver.static_descriptor(precursor)[1].get('handoff_id')
                except Exception: pass
            return fields.get('handoff_id')
        if suffix=='campaign': return fields.get('campaign_id')
        if suffix=='steps': return fields.get('steps','').replace(',','>')
        if suffix=='token': return fields.get('campaign_id','').split('-',1)[1] if '-' in fields.get('campaign_id','') else None
        if suffix=='indicator': return primary_indicator(fields)
    if prefix=='bash':
        if suffix=='role': return 'advanced_syntax' if aid.startswith('bash-advanced-') else graph_role(fields.get('steps',''))
        if suffix=='feature': return fields.get('feature')
        if suffix=='primitive': return fields.get('primitive')
        if suffix=='steps': return fields.get('steps','').replace(',','>')
        if suffix=='campaign': return fields.get('campaign_id')
        if suffix=='token': return fields.get('campaign_id','').split('-',1)[1] if '-' in fields.get('campaign_id','') else None
        if suffix=='indicator': return primary_indicator(fields)
    if prefix=='nodejs':
        if suffix=='role': return fields.get('role') or graph_role(fields.get('steps',''))
        if suffix=='attack': return attack_for(fields,prefix)
        if suffix=='steps': return fields.get('steps','').replace(',','>')
        if suffix=='campaign': return fields.get('campaign_id')
        if suffix=='token': return fields.get('campaign_id','').split('-',1)[1] if '-' in fields.get('campaign_id','') else None
        if suffix=='indicator': return primary_indicator(fields)
    if prefix=='polyglot':
        if suffix=='role': return fields.get('role')
        if suffix=='attack': return fields.get('attack')
        if suffix=='steps': return fields.get('steps','').replace(',','>')
        if suffix in ('stage-count','count'): return fields.get('stage_count') or fields.get('stageCount')
        if suffix in ('stage-profile','profile'): return fields.get('stage_profile')
        if suffix=='obfuscation': return fields.get('obfuscation_profile')
        if suffix=='language': return fields.get('next_language')
        if suffix=='campaign': return fields.get('campaign_id')
        if suffix=='url': return fields.get('url')
        if suffix=='path': return fields.get('file_path')
        if suffix=='host':
            url=fields.get('url','');return urlsplit(url).hostname
        if suffix=='leaf':
            path=fields.get('file_path','');return re.split(r'[/\\]',path.rstrip('/\\'))[-1] if path else None
        if suffix=='token': return fields.get('campaign_id','').split('-',1)[1] if '-' in fields.get('campaign_id','') else None
    return None

def main():
    start=json.loads(START.read_text())
    answers={}; missing=[]
    for q in start['questions']:
        fn=q['artifact'].split('->')[-1].strip()
        archive=q['artifact'].split('->')[0].strip()
        mset=re.search(r'evidence-(\d+)\.zip$',archive)
        p=(ROOT/mset.group(1)/fn) if mset else (ROOT/fn)
        if not p.exists():
            # remote-write.js carries the reversed base64 JSON in a literal.
            source=p.read_text(errors='replace') if p.exists() else ''
            m=re.search(r'packedText\s*=\s*"([^"]+)"',source)
            if m and 'reverse()' in source:
                import base64
                try:
                    raw=base64.b64decode(m.group(1))[::-1]
                    obj=json.loads(raw.decode()); fields={k:(str(v) if not isinstance(v,list) else '>'.join(map(str,v))) for k,v in obj.items()}
                    if isinstance(obj.get('values'),dict): fields.update({k:str(v) for k,v in obj['values'].items()})
                    if 'stageCount' in fields: fields['stage_count']=fields['stageCount']
                    plain,fields=raw.decode(),fields
                except Exception: pass
                else:
                    fields={}
            else:
                fields={}
            if not fields:
                missing.append((q['id'],fn,'file missing or no static descriptor')); continue
        else:
            try: plain,fields=solver.static_descriptor(p)
            except Exception as exc:
                missing.append((q['id'],fn,'static parse error '+type(exc).__name__)); continue
            source=p.read_text(errors='replace')
        if not fields:
            missing.append((q['id'],fn,'no static descriptor')); continue
        v=value_for(q,fields,source,fn)
        if v is None:
            missing.append((q['id'],fn,'unmapped; fields='+','.join(fields))); continue
        answers[q['id']]=str(v)
    OUT.write_text(json.dumps(answers,indent=2,sort_keys=True)+'\n')
    print('questions',len(start['questions']),'answers',len(answers),'missing',len(missing))
    for m in missing: print('MISSING',*m)
    print('output',OUT)

if __name__=='__main__': main()
