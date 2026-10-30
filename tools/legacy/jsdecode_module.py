import re,ast,base64,json,urllib.parse
def decode_candidates(s):
 cs=[]
 for m in re.finditer(r'(?:var|let|const)\s+([\w$]+)\s*=\s*\[([0-9a-fA-FxX,\s]+)\]',s):
  try:
   a=bytes(ast.literal_eval('['+m.group(2)+']'))
   if len(a)>30:cs.append((m.group(1),a))
  except:pass
 # concatenated arrays
 if len(cs)>1:
  for i in range(len(cs)):
   for j in range(i+1,min(len(cs),i+5)):
    cs.append((cs[i][0]+'+'+cs[j][0],cs[i][1]+cs[j][1]))
 for m in re.finditer(r'["\']([^"\']{40,})["\']',s):
  z=m.group(1)
  try:
   if re.search(r'%(?:[0-9a-fA-F]{2})',z): cs.append(('percent',urllib.parse.unquote_to_bytes(z)))
   if re.fullmatch(r'[0-9]+(?:-[0-9]+)+',z): cs.append(('decimal_string',bytes(map(int,z.split('-')))))
   if re.fullmatch(r'[0-9a-fA-F:]+',z) and len(z)>40: cs.append(('hex_string',bytes.fromhex(z.replace(':',''))))
   if re.fullmatch(r'[A-Za-z0-9+/=_-]+',z):
    cs.append(('base64_string',base64.b64decode(z+'='*((-len(z))%4))))
  except:pass
 # Packed strings may be assembled from adjacent literal chunks.
 m=re.search(r'packedText\s*=\s*((?:"[^"]*"\s*\+?\s*)+);',s)
 if m:
  z=''.join(re.findall(r'"([^"]*)"',m.group(1)))
  try:
   if re.fullmatch(r'[0-9a-fA-F:]+',z): cs.append(('packed_hex',bytes.fromhex(z.replace(':',''))))
   elif re.fullmatch(r'[0-9]+(?:-[0-9]+)+',z): cs.append(('packed_decimal',bytes(map(int,z.split('-')))))
   else: cs.append(('packed_b64',base64.b64decode(z+'='*((-len(z))%4))))
  except: pass
 # build repeated xor keys from short numeric arrays
 keys=[]
 for m in re.finditer(r'(?:var|let|const)\s+([\w$]+)\s*=\s*\[([0-9a-fA-FxX,\s]+)\]',s):
  try:
   a=bytes(ast.literal_eval('['+m.group(2)+']'))
   if 1<len(a)<=32:keys.append((m.group(1),a))
  except:pass
 for name,b in list(cs):
  variants=[(name,b),(name+' reverse',b[::-1])]
  # Some JScript fixtures reverse the packed bytes before applying a fixed XOR.
  for k in range(1,256):
   variants.append((name+f' reverse-xor{k}',bytes(x^k for x in b[::-1])))
   variants.append((name+f' reverse-sub{k}',bytes((x-k)%256 for x in b[::-1])))
   variants.append((name+f' reverse-add{k}',bytes((x+k)%256 for x in b[::-1])))
  dec=s[s.find('decode_'):s.find('recover_')]
  if re.search(r'previous\s*=\s*\d+',dec) and re.search(r'\^\s*previous',dec):
   prev=int(re.search(r'previous\s*=\s*(\d+)',dec).group(1)); out=[]
   for v in b: out.append(v^prev); prev=v
   variants.append((name+' chained-xor',bytes(out)))
   prev=int(re.search(r'previous\s*=\s*(\d+)',dec).group(1)); out=[]
   for v in b[::-1]: out.append(v^prev); prev=v
   variants.append((name+' reverse-chained-xor',bytes(out)))
  for k in range(1,256):
   variants.append((name+f' xor{k}',bytes(x^k for x in b)))
   variants.append((name+f' sub{k}',bytes((x-k)%256 for x in b)))
   variants.append((name+f' add{k}',bytes((x+k)%256 for x in b)))
  for kn,key in keys:
   variants.append((name+' xor '+kn,bytes(x^key[i%len(key)] for i,x in enumerate(b))))
   variants.append((name+' reverse xor '+kn,bytes(x^key[i%len(key)] for i,x in enumerate(b[::-1]))))
  for n,t in variants:
   txt=t.decode('utf-8','ignore').strip('\x00\r\n ')
   if txt.startswith('{'):
    try:
     o=json.loads(txt);return n,o
    except Exception: pass
  
 return None
