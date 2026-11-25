import {inspect} from "./engine.mjs";
/** Trusted text-only integration. Provider must honour AbortSignal and not execute tools. */
export function createGuardedModel({provider,protectedMarkers=[],policy="strict",timeoutMs=10000}){
  if(typeof provider!=="function")throw new TypeError("Provider required");
  if(!Number.isInteger(timeoutMs)||timeoutMs<10||timeoutMs>60000)throw new TypeError("Invalid timeout");
  const markers=Object.freeze([...protectedMarkers]);
  inspect("",{protectedMarkers:markers,policy});
  return async function guardedModel(text,{source="user"}={}){
    const summary=r=>({decision:r.decision,findings:r.findings,riskScore:r.riskScore});
    let input;
    try{input=inspect(text,{source,policy,protectedMarkers:markers});if(!text.trim())throw new TypeError();}catch{return {status:"input_invalid",input:null,output:null,text:null};}
    if(input.sanitisedText===null)return {status:"input_withheld",input:summary(input),output:null,text:null};
    const controller=new AbortController();
    let timer,response,timedOut=false;
    try{
      response=await Promise.race([
        Promise.resolve().then(()=>provider(input.sanitisedText,{signal:controller.signal})),
        new Promise((_,reject)=>{timer=setTimeout(()=>{timedOut=true;controller.abort();reject(Error("Deadline exceeded"));},timeoutMs);})
      ]);
    }catch{return {status:timedOut?"provider_timeout":"provider_failed",input:summary(input),output:null,text:null};}
    finally{clearTimeout(timer);}
    if(timedOut)return {status:"provider_timeout",input:summary(input),output:null,text:null};
    let output;
    try{output=inspect(response,{direction:"output",policy,protectedMarkers:markers});if(!response.trim())throw new TypeError();}catch{return {status:"output_invalid",input:summary(input),output:null,text:null};}
    return {status:output.sanitisedText===null?"output_withheld":"completed",input:summary(input),output:summary(output),text:output.sanitisedText};
  };
}
