import os,hashlib,json,time,uuid,platform,shutil
class ForensicManager:
 def __init__(self,root=None):
  self.root=root or os.path.join(os.path.dirname(__file__),'cases'); os.makedirs(self.root,exist_ok=True)
  self.case=None
 def create_case(self,name,examiner=''): 
  cid=str(uuid.uuid4())[:8]; self.case={'id':cid,'name':name,'examiner':examiner,'created':time.strftime('%Y-%m-%d %H:%M:%S'),'host':platform.node(),'events':[]}
  self._save(); return self.case
 def load_latest(self):
  fs=sorted([x for x in os.listdir(self.root) if x.endswith('.json')])
  if fs:
   with open(os.path.join(self.root,fs[-1]),encoding='utf-8') as f:self.case=json.load(f)
  return self.case
 def add_event(self,event,details=None):
  if not self.case:self.create_case('Untitled Case')
  self.case['events'].append({'time':time.strftime('%Y-%m-%d %H:%M:%S'),'event':event,'details':details or {}}); self._save()
 def hash_file(self,path):
  h=hashlib.sha256()
  with open(path,'rb') as f:
   for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
  return h.hexdigest()
 def _save(self):
  with open(os.path.join(self.root,self.case['id']+'.json'),'w',encoding='utf-8') as f:json.dump(self.case,f,indent=2)
