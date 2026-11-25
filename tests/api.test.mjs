import test from "node:test";
import assert from "node:assert/strict";
import {createHash,randomBytes} from "node:crypto";
import {createServer,loadConfig} from "../server.mjs";
const token=randomBytes(32).toString("base64url"),other=randomBytes(32).toString("base64url");
const digest=s=>createHash("sha256").update(s).digest("hex");
const marker="SYNTHETIC-PROTECTED-MARKER";
const env={PS_CLIENTS_JSON:JSON.stringify([{id:"input-client",sha256:digest(token),scopes:["input"]},{id:"output-client",sha256:digest(other),scopes:["output"]}]),PS_PROTECTED_MARKERS_JSON:JSON.stringify([marker]),PS_RATE_PER_MINUTE:"30"};
async function fixture(t,override={}){
  const logs=[];const config=loadConfig({...env,...override});
  const server=createServer(config,{audit:e=>logs.push(e)});
  await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
  const url="http://127.0.0.1:"+server.address().port;
  config.hosts.push(url.slice(7));
  t.after(()=>new Promise(resolve=>server.close(resolve)));
  const post=(direction,payload,key=token,headers={})=>fetch(url+"/v1/inspect/"+direction,{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+key,...headers},body:typeof payload==="string"?payload:JSON.stringify(payload)});
  return {post,url,logs};
}
test("authentication and scope enforcement",async t=>{const {post}=await fixture(t);assert.equal((await post("input",{text:"hello"},"bad")).status,401);assert.equal((await post("output",{text:"hello"})).status,403);assert.equal((await post("input",{text:"hello"},other)).status,403);});
test("strict policy, no payload in audit metadata",async t=>{const {post,logs}=await fixture(t);const secret="demo@example.com";const r=await post("input",{text:secret});assert.equal(r.status,200);assert.equal(r.headers.get("cache-control"),"no-store");const b=await r.json();assert.equal(b.decision,"block");assert.equal(b.sanitisedText,null);assert.ok(!JSON.stringify(b).includes(secret));assert.ok(!JSON.stringify(logs).includes(secret));assert.equal(logs[0].clientId,"input-client");assert.ok(logs[0].ruleIds.includes("DLP-01"));});
test("protected marker enforced on output and input",async t=>{const {post}=await fixture(t);for(const [dir,k] of [["input",token],["output",other]]){const r=await post(dir,{text:marker},k);const b=await r.json();assert.equal(b.decision,"block");assert.equal(b.sanitisedText,null);assert.ok(!JSON.stringify(b).includes(marker));}});
test("client cannot override policy or direction",async t=>{const {post}=await fixture(t);for(const p of [{text:"hello",policy:"standard"},{text:"hello",direction:"output"},{text:"hello",protectedMarkers:[]},{text:"hello",source:"system"},{text:[]},{text:" "}])assert.equal((await post("input",p)).status,400);});
test("body limit, malformed JSON and content type",async t=>{const {post}=await fixture(t);assert.equal((await post("input","{broken")).status,400);assert.equal((await post("input",{text:"a".repeat(140000)})).status,413);assert.equal((await post("input",{text:"a".repeat(20001)})).status,400);assert.equal((await post("input",{text:"ok"},token,{"Content-Type":"text/plain"})).status,415);});
test("cross-origin browser requests denied",async t=>{const {post}=await fixture(t);assert.equal((await post("input",{text:"hello"},token,{Origin:"https://example.invalid"})).status,403);});
test("rate limit per credential",async t=>{const {post}=await fixture(t,{PS_RATE_PER_MINUTE:"2"});for(let i=0;i<2;i++)assert.equal((await post("input",{text:"hello"})).status,200);const r=await post("input",{text:"hello"});assert.equal(r.status,429);assert.ok(Number(r.headers.get("retry-after"))>0);assert.equal((await post("output",{text:"hello"},other)).status,200);});
test("disabled API, health and static security headers",async t=>{const {post,url}=await fixture(t,{PS_CLIENTS_JSON:"[]"});assert.equal((await post("input",{text:"hello"})).status,503);assert.deepEqual(await (await fetch(url+"/healthz")).json(),{status:"ok",apiEnabled:false});const r=await fetch(url);assert.equal(r.status,200);assert.match(r.headers.get("content-security-policy"),/frame-ancestors 'none'/);assert.equal((await fetch(url+"/.env")).status,404);});
test("reject insecure non-loopback and malformed config",()=>{assert.throws(()=>loadConfig({PS_BIND:"0.0.0.0"}));assert.throws(()=>loadConfig({PS_POLICY:"none"}));assert.throws(()=>loadConfig({PS_CLIENTS_JSON:"[{}]"}));assert.throws(()=>loadConfig({PS_PROTECTED_MARKERS_JSON:'["short"]'}));});
