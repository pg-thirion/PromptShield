import {inspect} from "./engine.mjs";
import {examples,evaluate} from "./cases.mjs";
import {inspectContext} from "./context.mjs";
import {createHistory,evaluationReport} from "./analytics.mjs";
const $=id=>document.getElementById(id);
const input=$("prompt"), direction=$("direction"), source=$("source"), markers=$("markers");
let count=0, forwardable=null, report=null;
const policy=$("policy"),history=createHistory();
const descriptions={allow:"No configured rule triggered. This does not establish safety.",redact:"Sensitive spans removed. Review the sanitised text before forwarding.",review:"Suspicious instructions detected. Hold for human review.",block:"Policy blocks forwarding. Investigate the rule findings."};
function sync(){ $("length").textContent=input.value.length.toLocaleString()+" / 20,000"; }
function reset(){forwardable=null;$("empty").hidden=false;$("result").hidden=true;$("decision").textContent="Not inspected";$("decision").className="pill neutral";$("copy").disabled=true;$("error").textContent="";}
for(const e of [input,direction,source,markers,policy])e.addEventListener("input",()=>{sync();reset();});
function addButton(example){const b=document.createElement("button");b.textContent=example.label;b.addEventListener("click",()=>{input.value=example.text;direction.value=example.options?.direction??"input";source.value=example.options?.source??"user";markers.value=(example.options?.protectedMarkers??[]).join("\n");policy.value=example.options?.policy??"standard";sync();reset();input.focus();});$("examples").append(b);}
examples.forEach(addButton);
$("clear").addEventListener("click",()=>{input.value="";markers.value="";direction.value="input";source.value="user";policy.value="standard";sync();reset();input.focus();});
$("inspect").addEventListener("click",()=>{
  reset();
  if(!input.value.trim()){$("error").textContent="Enter text to inspect.";return;}
  let r;
  try{r=inspect(input.value,{direction:direction.value,source:source.value,policy:policy.value,protectedMarkers:markers.value.split(/\r?\n/).filter(Boolean)});}catch(e){$("error").textContent=e.message;return;}
  history.record(r);count++;$("scan-count").textContent=count+" "+(count===1?"scan":"scans");
  $("empty").hidden=true;$("result").hidden=false;
  $("decision").textContent=r.decision.toUpperCase();$("decision").className="pill "+r.decision;
  $("score").replaceChildren(document.createTextNode(String(r.riskScore)));const denominator=document.createElement("span");denominator.textContent="/100";$("score").append(denominator);
  $("meter").style.width=r.riskScore+"%";$("meter").className=r.decision;
  $("decision-detail").textContent=descriptions[r.decision];$("finding-count").textContent="("+r.findings.length+")";
  $("findings").replaceChildren();
  for(const f of r.findings){const el=document.createElement("div");el.className="finding";const row=document.createElement("div");const label=document.createElement("strong");label.textContent=f.id+" · "+f.category.replaceAll("_"," ");const sev=document.createElement("span");sev.className="severity "+f.severity;sev.textContent=f.severity;row.append(label,sev);const p=document.createElement("p");p.textContent=f.description+" ("+f.count+")";el.append(row,p);$("findings").append(el);}
  if(!r.findings.length)$("findings").textContent="No configured rule matched.";
  forwardable=r.sanitisedText;$("sanitised").textContent=forwardable??"Withheld by policy.";$("redactions").textContent=r.redactionCount+" sensitive span(s) identified.";$("copy").disabled=forwardable===null;
});
$("copy").addEventListener("click",async()=>{if(forwardable===null)return;try{await navigator.clipboard.writeText(forwardable);$("copy").textContent="Copied";setTimeout(()=>$("copy").textContent="Copy",1000);}catch{$("error").textContent="Clipboard unavailable. Select and copy the forwardable text manually.";}});

const views=["work","eval","context","history"];
function tab(selected){for(const v of views){$(v+"-view").hidden=v!==selected;$(v+"-tab").setAttribute("aria-pressed",String(v===selected));}if(selected==="history")renderHistory();}
for(const v of views)$(v+"-tab").addEventListener("click",()=>tab(v));
function tableRow(values){const tr=document.createElement("tr");for(const t of values){const td=document.createElement("td");td.textContent=String(t);tr.append(td);}return tr;}
function renderEvaluation(){
  if(!report)return;
  const filter=$("eval-filter").value;
  $("evaluation-rows").replaceChildren();
  for(const r of report.cases.filter(r=>filter==="all"||(filter==="match"?r.match:!r.match))){const tr=tableRow([r.label,r.expected,r.actual,r.match?"Match":"Mismatch"]);tr.lastElementChild.className=r.match?"pass":"fail";$("evaluation-rows").append(tr);}
}
function metricCard(label,value,note){const card=document.createElement("article");for(const [tag,t] of [["small",label],["strong",value],["p",note]]){const e=document.createElement(tag);e.textContent=t;card.append(e);}return card;}
const pct=n=>n===null?"N/A":(n*100).toFixed(1)+"%";
$("evaluate").addEventListener("click",()=>{
  report=evaluationReport(evaluate(inspect));const m=report.metrics;
  $("metrics").replaceChildren(...[["EXACT DECISIONS",m.exactMatches+" / "+m.cases,"Curated cases"],["BLOCK PRECISION",pct(m.precision),"Correct predicted blocks"],["BLOCK RECALL",pct(m.recall),"Expected blocks detected"],["BLOCK F1",pct(m.f1),"Precision / recall balance"],["FALSE BLOCK RATE",pct(m.falsePositiveRate),"Non-block cases incorrectly blocked"],["MISSED BLOCKS",String(m.missedBlocks),"Expected block, not blocked"]].map(x=>metricCard(...x)));
  const table=document.createElement("table"),head=document.createElement("thead"),body=document.createElement("tbody");
  const ds=["allow","redact","review","block"];const row=document.createElement("tr");
  for(const x of ["Expected / Actual",...ds]){const th=document.createElement("th");th.textContent=x;row.append(th);}head.append(row);
  for(const d of ds)body.append(tableRow([d,...ds.map(a=>m.matrix[d][a])]));
  table.append(head,body);$("confusion").replaceChildren(table);
  $("export-evaluation").disabled=false;renderEvaluation();
});
$("eval-filter").addEventListener("change",renderEvaluation);
function downloadJSON(name,value){
  const url=URL.createObjectURL(new Blob([JSON.stringify(value,null,2)],{type:"application/json"}));
  const a=document.createElement("a");a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
$("export-evaluation").addEventListener("click",()=>{if(report)downloadJSON("promptshield-evaluation.json",report);});
function renderHistory(){$("history-rows").replaceChildren();for(const e of history.list())$("history-rows").append(tableRow([new Date(e.at).toLocaleTimeString(),e.decision,e.policy,e.riskScore,e.ruleIds.join(", ")||"None"]));}
$("export-history").addEventListener("click",()=>downloadJSON("promptshield-session.json",{schemaVersion:1,entries:history.list()}));
$("clear-history").addEventListener("click",()=>{history.clear();renderHistory();});
function addSegment(text="",source="user"){
  if($("segments").children.length>=32)return;
  const card=document.createElement("div");card.className="segment finding";
  const label=document.createElement("label");label.textContent="Content source";
  const sel=document.createElement("select");sel.className="segment-source";
  for(const [v,t] of [["user","User message"],["retrieved","Retrieved document"],["tool","Tool response"]]){const opt=document.createElement("option");opt.value=v;opt.textContent=t;sel.append(opt);}sel.value=source;label.append(sel);
  const tlabel=document.createElement("label");tlabel.textContent="Segment text";const area=document.createElement("textarea");area.className="segment-text";area.maxLength=20000;area.value=text;tlabel.append(area);
  const remove=document.createElement("button");remove.textContent="Remove segment";remove.className="secondary";remove.addEventListener("click",()=>{card.remove();$("context-result").replaceChildren();$("add-segment").disabled=false;});
  for(const e of [sel,area])e.addEventListener("input",()=>$("context-result").replaceChildren());
  card.append(label,tlabel,remove);$("segments").append(card);$("add-segment").disabled=$("segments").children.length>=32;
}
addSegment("Summarise the public report.","user");addSegment("Public report: revenue increased.","retrieved");
$("add-segment").addEventListener("click",()=>{addSegment();$("context-result").replaceChildren();});
$("inspect-context").addEventListener("click",()=>{
  $("context-error").textContent="";$("context-result").replaceChildren();
  try{
    const items=[...$("segments").children].map(e=>({text:e.querySelector(".segment-text").value,source:e.querySelector(".segment-source").value}));
    const r=inspectContext(items,{policy:"strict"});
    const title=document.createElement("h3");title.textContent=r.decision==="allow"?"Context allowed":"Entire context withheld";
    const info=document.createElement("p");info.textContent="Strict input policy · risk "+r.riskScore+" / 100";
    const rules=document.createElement("p");rules.textContent="Triggered rules: "+([...new Set([...r.segments,...r.contextFindings].flatMap(e=>e.findings.map(f=>f.id)))].join(", ")||"None");
    $("context-result").append(title,info,rules);
  }catch(e){$("context-error").textContent=e.message;}
});
sync();
