import os, hashlib, json, time, secrets, shutil, subprocess, platform

class SanitizationEngine:
    def __init__(self, log_path=None):
        self.log_path=log_path or os.path.join(os.path.dirname(os.path.dirname(__file__)),'dataresq_audit.jsonl')
    def sha256(self,path,chunk=1024*1024):
        h=hashlib.sha256()
        with open(path,'rb') as f:
            while True:
                b=f.read(chunk)
                if not b: break
                h.update(b)
        return h.hexdigest()
    def secure_delete_file(self,path,passes=1,pattern='random',verify=True):
        if not os.path.isfile(path): raise FileNotFoundError(path)
        size=os.path.getsize(path); before=self.sha256(path)
        with open(path,'r+b',buffering=0) as f:
            for p in range(max(1,int(passes))):
                f.seek(0); left=size
                while left:
                    n=min(1024*1024,left)
                    data=(b'\x00'*n) if pattern=='zero' else secrets.token_bytes(n)
                    f.write(data); left-=n
                f.flush(); os.fsync(f.fileno())
        # final zero pass is useful for deterministic verification on ordinary filesystems
        if verify:
            with open(path,'rb') as f: all_zero=(f.read() == b'\x00'*size) if size<=16*1024*1024 else self._sample_zero(f,size)
        else: all_zero=True
        os.remove(path)
        ok=not os.path.exists(path)
        rec={'timestamp':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'operation':'FILE_ERASURE','path':os.path.abspath(path),'size':size,'original_sha256':before,'passes':passes,'verification':bool(all_zero),'deleted':ok}
        self._log(rec); return rec
    def _sample_zero(self,f,size):
        points=[0,max(0,size//2),max(0,size-1024*1024)]
        for p in points:
            f.seek(p); b=f.read(min(1024*1024,size-p))
            if any(b): return False
        return True
    def secure_delete_folder(self,path,passes=1):
        if not os.path.isdir(path): raise NotADirectoryError(path)
        records=[]
        for root,dirs,files in os.walk(path,topdown=False):
            for n in files:
                try: records.append(self.secure_delete_file(os.path.join(root,n),passes))
                except Exception as e: self._log({'operation':'FILE_ERASURE_ERROR','path':os.path.join(root,n),'error':str(e)})
            for d in dirs:
                try: os.rmdir(os.path.join(root,d))
                except OSError: pass
        try: os.rmdir(path)
        except OSError: pass
        return records
    def sanitize_free_space(self, drive, progress=None):
        if platform.system()!='Windows':
            raise RuntimeError('Drive free-space sanitization currently supports Windows.')
        drive=os.path.abspath(drive)
        if not drive.endswith('\\'): drive+='\\'
        if not (len(drive)>=3 and drive[1:3]==':\\'):
            raise ValueError('Select a Windows drive such as D:')
        cmd=['cipher','/w:'+drive]
        p=subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, encoding='mbcs', errors='replace', bufsize=1)
        output=[]; phase=0
        if progress: progress(0)
        for line in iter(p.stdout.readline, ''):
            if not line: break
            output.append(line); low=line.lower()
            if 'writing 0x00' in low: phase=max(phase,1)
            elif 'writing ff' in low or 'writing 0xff' in low: phase=max(phase,2)
            elif 'writing random' in low: phase=max(phase,3)
            if progress: progress(min(95, phase*30))
        p.wait()
        if progress: progress(100 if p.returncode==0 else min(100,phase*30))
        rec={'timestamp':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
             'operation':'FREE_SPACE_SANITIZATION','drive':drive,'command':'cipher /w',
             'returncode':p.returncode,'success':p.returncode==0,'output':''.join(output)[-8000:]}
        self._log(rec); return rec

    def _delete_accessible_contents(self, drive, progress=None):
        root=os.path.abspath(drive); removed=0; errors=[]
        for current,dirs,files in os.walk(root, topdown=True):
            for name in list(files):
                path=os.path.join(current,name)
                try: os.remove(path); removed += 1
                except (PermissionError,OSError) as e: errors.append({'path':path,'error':str(e)})
            for name in list(dirs):
                path=os.path.join(current,name)
                try: os.rmdir(path)
                except (PermissionError,OSError): pass
            if progress: progress(5)
        return removed,errors

    def sanitize_drive(self, drive, progress=None):
        if platform.system()!='Windows':
            raise RuntimeError('Complete drive sanitization currently supports Windows.')
        drive=os.path.abspath(drive)
        if not drive.endswith('\\'): drive+='\\'
        if len(drive)<3 or drive[1:3] != ':\\':
            raise ValueError('Select a Windows drive such as D:')
        if drive.upper().startswith('C:\\'):
            raise RuntimeError('System drive C: is protected by DataResQ and cannot be emptied.')
        if progress: progress(2)
        removed,errors=self._delete_accessible_contents(
            drive, lambda _: progress(5) if progress else None)
        if progress: progress(20)
        free=self.sanitize_free_space(
            drive, progress=lambda v: progress(20+int(v*.8)) if progress else None)
        remaining=sum(len(files) for _,_,files in os.walk(drive))
        success=free.get('success',False) and remaining==0
        result={'timestamp':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
                'operation':'DRIVE_SANITIZATION','drive':drive,'files_removed':removed,
                'remaining_accessible_files':remaining,'delete_errors':errors[-100:],
                'free_space_success':free.get('success',False),'success':success}
        self._log(result)
        if progress: progress(100)
        return result

    def _log(self,record):
        os.makedirs(os.path.dirname(self.log_path),exist_ok=True)
        with open(self.log_path,'a',encoding='utf-8') as f: f.write(json.dumps(record,ensure_ascii=False)+'\n')
