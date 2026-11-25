import {inspect} from "./engine.mjs";

/**
 * Atomic context inspection. No individual text is released if any segment or
 * combined representation triggers a security rule. Bound both item count and
 * total size. The trusted application supplies provenance and configuration.
 */
export function inspectContext(items,{direction="input",protectedMarkers=[],policy="strict"}={}){
  if(!Array.isArray(items)||!items.length||items.length>32)throw new TypeError("Context requires 1–32 segments");
  let total=0;
  for(const i of items){
    if(!i||typeof i!=="object"||Array.isArray(i)||Object.keys(i).some(k=>!["text","source"].includes(k))||typeof i.text!=="string"||!i.text.trim()||!["user","retrieved","tool"].includes(i.source??"user"))throw new TypeError("Invalid context segment");
    total+=i.text.length;
  }
  if(total+items.length-1>20000)throw new TypeError("Context exceeds 20,000 characters");
  const opts={direction,protectedMarkers,policy};
  const results=items.map(i=>inspect(i.text,{...opts,source:i.source??"user"}));
  // Joining with and without separators can catch split instructions and markers.
  const aggregateSource=items.every(i=>(i.source??"user")==="user")?"user":"retrieved";
  const joins=[items.map(i=>i.text).join("\n"),items.map(i=>i.text).join("")];
  const combined=[...new Set(joins)].map(text=>inspect(text,{...opts,source:aggregateSource}));
  const all=[...results,...combined];
  const held=all.some(r=>r.decision!=="allow");
  const summary=r=>({decision:r.decision,riskScore:r.riskScore,findings:r.findings,source:r.source});
  return {version:"1.2.0",policy,direction,decision:held?"block":"allow",riskScore:Math.max(...all.map(r=>r.riskScore)),segments:results.map(summary),contextFindings:combined.map(summary),sanitisedSegments:held?null:results.map(r=>r.sanitisedText)};
}
