const decisions=["allow","redact","review","block"];
const ratio=(a,b)=>b===0?null:a/b;
/** Exact decision confusion matrix plus binary block precision/recall. */
export function summarise(results){
  if(!Array.isArray(results)||results.some(r=>!decisions.includes(r.expected)||!decisions.includes(r.actual)))throw new TypeError("Invalid evaluation results");
  const matrix=Object.fromEntries(decisions.map(e=>[e,Object.fromEntries(decisions.map(a=>[a,0]))]));
  for(const r of results)matrix[r.expected][r.actual]++;
  const exact=decisions.reduce((n,d)=>n+matrix[d][d],0);
  const tp=matrix.block.block,fp=decisions.filter(d=>d!=="block").reduce((n,d)=>n+matrix[d].block,0);
  const fn=decisions.filter(d=>d!=="block").reduce((n,d)=>n+matrix.block[d],0);
  const tn=results.length-tp-fp-fn;
  const precision=ratio(tp,tp+fp),recall=ratio(tp,tp+fn);
  const f1=ratio(2*tp,2*tp+fp+fn);
  return {cases:results.length,exactMatches:exact,accuracy:ratio(exact,results.length),precision,recall,f1,falsePositiveRate:ratio(fp,fp+tn),missedBlocks:fn,falseBlocks:fp,matrix};
}
/** Export only trusted scenario labels and decision metadata, never prompt text. */
export function evaluationReport(results){
  return {schemaVersion:1,scope:"curated-synthetic",metrics:summarise(results),cases:results.map(({label,expected,actual})=>({label,expected,actual,match:expected===actual}))};
}
/** Session summaries never retain submitted or sanitised text. */
export function createHistory(limit=50){
  if(!Number.isInteger(limit)||limit<1||limit>200)throw new TypeError("Invalid history limit");
  const entries=[];
  return {record(result,at=new Date().toISOString()){
    if(!decisions.includes(result.decision))throw new TypeError("Invalid inspection");
    entries.unshift({at,decision:result.decision,policy:result.policy,direction:result.direction,source:result.source,riskScore:result.riskScore,ruleIds:result.findings.map(f=>f.id),redactionCount:result.redactionCount});
    if(entries.length>limit)entries.length=limit;
  },list(){return entries.map(e=>({...e,ruleIds:[...e.ruleIds]}));},clear(){entries.length=0;}};
}
