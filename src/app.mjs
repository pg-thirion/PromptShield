import {inspect} from "./engine.mjs";
import {examples,evaluate} from "./cases.mjs";
const $=id=>document.getElementById(id);
const input=$("prompt"), direction=$("direction"), source=$("source"), markers=$("markers");
let count=0, forwardable=null;
const descriptions={allow:"No configured rule triggered. This does not establish safety.",redact:"Sensitive spans removed. Review the sanitised text before forwarding.",review:"Suspicious instructions detected. Hold for human review.",block:"Policy blocks forwarding. Investigate the rule findings."};
function sync(){ $("length").textContent=input.value.length.toLocaleString()+" / 20,000";$("marker-area").hidden=direction.value!=="output"; }
function reset(){forwardable=null;$("empty").hidden=false;$("result").hidden=true;$("decision").textContent="Not inspected";$("decision").className="pill neutral";$("copy").disabled=true;$("error").textContent="";}
for(const e of [input,direction,source,markers])e.addEventListener("input",()=>{sync();reset();});
function addButton(example){const b=document.createElement("button");b.textContent=example.label;b.addEventListener("click",()=>{input.value=example.text;direction.value=example.options?.direction??"input";source.value=example.options?.source??"user";markers.value=(example.options?.protectedMarkers??[]).join("\n");sync();reset();input.focus();});$("examples").append(b);}
examples.forEach(addButton);
$("clear").addEventListener("click",()=>{input.value="";markers.value="";direction.value="input";source.value="user";sync();reset();input.focus();});
$("inspect").addEventListener("click",()=>{
  reset();
  if(!input.value.trim()){$("error").textContent="Enter text to inspect.";return;}
  let r;
  try{r=inspect(input.value,{direction:direction.value,source:source.value,protectedMarkers:direction.value==="output"?markers.value.split(/\r?\n/).filter(Boolean):[]});}catch(e){$("error").textContent=e.message;return;}
  count++;$("scan-count").textContent=count+" "+(count===1?"scan":"scans");
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
function tab(evaluation){$("work-view").hidden=evaluation;$("eval-view").hidden=!evaluation;$("work-tab").setAttribute("aria-pressed",String(!evaluation));$("eval-tab").setAttribute("aria-pressed",String(evaluation));}
$("work-tab").addEventListener("click",()=>tab(false));$("eval-tab").addEventListener("click",()=>tab(true));
$("evaluate").addEventListener("click",()=>{
  const results=evaluate(inspect), correct=results.filter(r=>r.actual===r.expected).length;
  const misses=results.filter(r=>r.expected==="block"&&r.actual!=="block").length;
  const falseBlocks=results.filter(r=>r.expected==="allow"&&r.actual==="block").length;
  $("metrics").replaceChildren();
  for(const [label,value,note] of [["EXACT DECISIONS",correct+" / "+results.length,"Curated cases only"],["MISSED BLOCKS",String(misses),"Expected block, not blocked"],["FALSE BLOCKS",String(falseBlocks),"Expected allow, blocked"]]){const card=document.createElement("article");for(const [tag,t] of [["small",label],["strong",value],["p",note]]){const e=document.createElement(tag);e.textContent=t;card.append(e);}$("metrics").append(card);}
  $("evaluation-rows").replaceChildren();for(const r of results){const tr=document.createElement("tr");for(const t of [r.label,r.expected,r.actual,r.actual===r.expected?"Match":"Mismatch"]){const td=document.createElement("td");td.textContent=t;tr.append(td);}tr.lastElementChild.className=r.actual===r.expected?"pass":"fail";$("evaluation-rows").append(tr);}
});
sync();
