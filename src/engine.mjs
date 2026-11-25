// PromptShield deterministic inspection engine. No network, storage or model calls.
export function inspect(input, options={}) {
  const MAX=20000;
  if(typeof input!=="string" || input.length>MAX) throw new TypeError("Input must be text of at most 20,000 characters.");
  const direction=options.direction??"input", source=options.source??"user";
  if(!["input","output"].includes(direction)||!["user","retrieved","tool"].includes(source)) throw new TypeError("Invalid direction or source.");
  const markers=options.protectedMarkers??[];
  if(!Array.isArray(markers)||markers.length>20||markers.some(m=>typeof m!=="string"||m.length<8||m.length>256)) throw new TypeError("Protected markers must be 8–256 characters, maximum 20.");
  const canonical=s=>s.normalize("NFKC").replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/g,"");
  const content=canonical(input);
  if(content.length>MAX) throw new TypeError("Normalised input exceeds limit.");
  const findings=[], spans=[];
  const add=(id,category,severity,description,count=1)=>{if(count) findings.push({id,category,severity,description,count});};
  const rules=[
    ["INJ-01","instruction_override","high","Attempts to override governing instructions.",/\b(?:ignore|disregard|forget|override|bypass)\b[\s\S]{0,75}\b(?:previous|prior|above|earlier|system|developer|safety|all)\b[\s\S]{0,35}\b(?:instructions?|rules?|prompts?|polic(?:y|ies)|constraints?|guidelines?)\b/i],
    ["INJ-02","prompt_extraction","high","Requests hidden instructions or privileged configuration.",/\b(?:reveal|show|print|display|expose|repeat|return|dump|give me|tell me)\b[\s\S]{0,65}\b(?:system prompt|developer (?:prompt|message|instructions?)|hidden instructions?|internal instructions?|secret prompt)\b/i],
    ["INJ-03","role_manipulation","high","Attempts to impersonate a privileged instruction channel.",/(?:\[\s*\/?(?:SYSTEM|INST|DEVELOPER)\s*\]|<\|(?:im_start|system|developer|endoftext)\|>|(?:^|\n)\s*(?:system|developer)\s*:\s*|you are now (?:an? )?(?:unrestricted|unfiltered|jailbroken)|developer mode (?:enabled|activated|on))/i],
    ["INJ-04","policy_bypass","high","Requests removal of safety or approval controls.",/\b(?:disable|remove|bypass|evade|turn off)\b[\s\S]{0,45}\b(?:safety filters?|guardrails?|security checks?|content filters?|approval checks?|human approval|moderation)\b/i],
    ["INJ-05","data_exfiltration","high","Requests transfer of sensitive information to an external destination.",/\b(?:send|upload|post|forward|transmit|export|exfiltrate)\b[\s\S]{0,90}\b(?:credentials?|passwords?|api keys?|customer (?:records?|data)|secrets?|access tokens?)\b[\s\S]{0,70}\b(?:https?:\/\/|external|webhook|attacker|remote server|to this email)\b/i],
    ["INJ-06","malicious_instruction","high","Requests credential theft or unauthorised disclosure.",/\b(?:steal|harvest|extract|dump|collect)\b[\s\S]{0,65}\b(?:passwords?|credentials?|session cookies?|access tokens?|private keys?)\b/i],
    ["INJ-07","suspicious_instruction","medium","Potential attempt to conceal actions or change instruction priority.",/\b(?:do not tell (?:the )?(?:user|administrator|analyst)|without (?:the )?(?:user's|user|human) (?:knowledge|consent|approval)|highest priority instruction|follow only these instructions|never reveal that you)\b/i]
  ];
  if(direction==="input") for(const [id,cat,sev,desc,re] of rules) if(re.test(content)) add(id,source==="user"?cat:"indirect_"+cat,sev,desc);
  if(input!==content) add("TXT-01","normalisation","info","Unicode normalisation or invisible-character removal changed the text.");
  function sensitive(id,cat,sev,desc,re,validate=()=>true) {
    let count=0;
    for(const m of content.matchAll(re)) if(validate(m[0])) {spans.push({start:m.index,end:m.index+m[0].length,cat});count++;}
    add(id,cat,sev,desc,count);
  }
  function luhn(s) {
    const d=s.replace(/\D/g,"");let sum=0,alternate=false;
    for(let i=d.length-1;i>=0;i--){let n=+d[i];if(alternate){n*=2;if(n>9)n-=9;}sum+=n;alternate=!alternate;}
    return sum%10===0;
  }
  function saId(s) {
    if(!luhn(s))return false;
    const yy=+s.slice(0,2),mm=+s.slice(2,4),dd=+s.slice(4,6);
    return [1900+yy,2000+yy].some(y=>{const d=new Date(Date.UTC(y,mm-1,dd));return d.getUTCMonth()===mm-1&&d.getUTCDate()===dd;});
  }
  sensitive("DLP-01","email","medium","Email address detected.",/\b[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9-]+(?:\.[A-Z0-9-]+)+\b/gi);
  sensitive("DLP-02","private_key","high","Private key material detected.",/-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/g);
  sensitive("DLP-03","api_token","high","Recognisable credential token detected.",/\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{15,})\b/g);
  sensitive("DLP-04","credential_assignment","high","Potential secret assignment detected.",/\b(?:password|passwd|api[_ -]?key|secret|access[_ -]?token|client[_ -]?secret)\s*[:=]\s*(?:"[^"\r\n]{4,}"|'[^'\r\n]{4,}'|[^\s,;]{6,})/gi);
  sensitive("DLP-05","payment_card","high","Luhn-valid payment card candidate detected.",/(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/g,s=>{const d=s.replace(/\D/g,"");return d.length>=13&&d.length<=19&&luhn(d)&&!(/^(\d)\1+$/.test(d))&&!(d.length===13&&saId(d));});
  sensitive("DLP-06","south_african_id","high","Checksum-valid South African ID candidate detected.",/(?<!\d)\d{13}(?!\d)/g,saId);
  sensitive("DLP-07","jwt","high","JWT-like token detected.",/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\b/g);
  sensitive("DLP-08","policy_identifier","medium","Insurance policy identifier candidate detected.",/\bPOL[- ]\d{5,15}\b/gi);
  if(direction==="output"){
    let count=0;
    for(const marker of markers){
      const m=canonical(marker);if(m.length<8)continue;
      let at=0;while((at=content.indexOf(m,at))!==-1){spans.push({start:at,end:at+m.length,cat:"protected_marker"});count++;at+=m.length;}
    }
    add("DLP-09","protected_marker","high","Caller-defined protected content appeared in output.",count);
  }
  spans.sort((a,b)=>a.start-b.start||b.end-a.end);
  const merged=[];
  for(const s of spans){const last=merged.at(-1);if(last&&s.start<last.end){last.end=Math.max(last.end,s.end);last.cat="sensitive";}else merged.push({...s});}
  let sanitised="",cursor=0;
  for(const s of merged){sanitised+=content.slice(cursor,s.start)+"["+s.cat.toUpperCase()+"]";cursor=s.end;}
  sanitised+=content.slice(cursor);
  const attack=findings.some(f=>f.id.startsWith("INJ-")&&f.severity==="high");
  const leak=findings.some(f=>f.id.startsWith("DLP-")&&f.severity==="high");
  const review=findings.some(f=>f.id.startsWith("INJ-"));
  const decision=attack||(direction==="output"&&leak)?"block":review?"review":merged.length?"redact":"allow";
  const score=Math.min(100,findings.reduce((n,f)=>n+(f.severity==="high"?45:f.severity==="medium"?20:0),0));
  return {version:"1.0.0",direction,source,decision,riskScore:score,findings,redactionCount:merged.length,sanitisedText:decision==="block"||decision==="review"?null:sanitised};
}
