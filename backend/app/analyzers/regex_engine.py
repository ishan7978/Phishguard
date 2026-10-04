from .patterns import COMPILED,URL_RE,EMAIL_RE,IP_RE
def analyze(text):
    out=[]
    for rid,cat,rx,sev,score,why in COMPILED:
        for m in rx.finditer(text):
            out.append({'rule_id':rid,'category':cat,'matched_text':m.group(0),'severity':sev,'score':score,'explanation':why,'source':'regex'})
    return out[:50]
def extract(text):
    return {'urls':sorted(set(x.rstrip('.,);]') for x in URL_RE.findall(text))), 'emails':sorted(set(EMAIL_RE.findall(text))), 'ips':sorted(set(IP_RE.findall(text)))}
