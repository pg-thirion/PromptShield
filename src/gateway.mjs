import {inspect} from "./engine.mjs";
/**
 * Trusted server-side integration helper. Never pass configuration directly from
 * an untrusted HTTP request. Provider receives only approved sanitised text.
 * Provider must be a trusted, text-only adapter with its own deadline.
 */
export function createGuardedModel({provider,protectedMarkers=[],policy="strict"}){
  if(typeof provider!=="function")throw new TypeError("Provider required");
  const markers=Object.freeze([...protectedMarkers]);
  inspect("",{protectedMarkers:markers,policy});
  return async function guardedModel(text,{source="user"}={}){
    const input=inspect(text,{source,policy,protectedMarkers:markers});
    const summary=r=>({decision:r.decision,findings:r.findings,riskScore:r.riskScore});
    if(input.sanitisedText===null)return {status:"input_withheld",input:summary(input),output:null,text:null};
    let response;
    try{response=await provider(input.sanitisedText);}catch{return {status:"provider_failed",input:summary(input),output:null,text:null};}
    let output;
    try{output=inspect(response,{direction:"output",policy,protectedMarkers:markers});}catch{return {status:"output_invalid",input:summary(input),output:null,text:null};}
    return {status:output.sanitisedText===null?"output_withheld":"completed",input:summary(input),output:summary(output),text:output.sanitisedText};
  };
}
