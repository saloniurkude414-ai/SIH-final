import os,html,json,time
class ReportBuilder:
 def __init__(self,root): self.root=root
 def build(self,data,out_path):
  e=html.escape
  sections=[]
  for title,items in data.get('sections',[]):
   rows=''.join(f'<tr><td>{e(str(k))}</td><td>{e(str(v))}</td></tr>' for k,v in items.items())
   sections.append(f'<h2>{e(title)}</h2><table>{rows}</table>')
  doc=f'''<!doctype html><html><head><meta charset="utf-8"><title>DataResQ Forensic Report</title><style>body{{font-family:Segoe UI,Arial;background:#071018;color:#dbe8f2;margin:40px}}h1{{color:#55bfff}}h2{{border-bottom:1px solid #203444;padding-bottom:8px}}table{{width:100%;border-collapse:collapse;margin:12px 0 28px}}td{{border:1px solid #243746;padding:9px}}td:first-child{{width:30%;color:#8db2c8}}.note{{color:#8da0ad}}</style></head><body><h1>DATARESQ — FORENSIC REPORT</h1><p class="note">Generated {e(time.strftime('%Y-%m-%d %H:%M:%S'))}</p>{''.join(sections)}<p class="note">DataResQ report • preserve original evidence separately and record authorization.</p></body></html>'''
  with open(out_path,'w',encoding='utf-8') as f:f.write(doc)
  return out_path
