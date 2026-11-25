import http from "node:http";
import {readFile} from "node:fs/promises";
import {createHash,randomUUID,timingSafeEqual} from "node:crypto";
import {pathToFileURL} from "node:url";
import {inspect} from "./src/engine.mjs";

const ASSETS=new Map([["/","index.html"],["/index.html","index.html"],["/src/style.css","src/style.css"],["/src/app.mjs","src/app.mjs"],["/src/engine.mjs","src/engine.mjs"],["/src/cases.mjs","src/cases.mjs"]]);
const MIME={html:"text/html; charset=utf-8",css:"text/css; charset=utf-8",mjs:"text/javascript; charset=utf-8"};
const HEADERS={"Cache-Control":"no-store","X-Content-Type-Options":"nosniff","Referrer-Policy":"no-referrer","X-Frame-Options":"DENY","Permissions-Policy":"camera=(), microphone=(), geolocation=()","Content-Security-Policy":"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"};
const hash=s=>createHash("sha256").update(s).digest();
const bounded=(v,min,max,name)=>{const n=Number(v);if(!Number.isInteger(n)||n<min||n>max)throw new Error("Invalid "+name);return n;};
export function loadConfig(env=process.env){
  const port=bounded(env.PORT??3000,1,65535,"PORT");
  const bind=env.PS_BIND??"127.0.0.1";
  if(!["127.0.0.1","0.0.0.0"].includes(bind))throw new Error("Invalid PS_BIND");
  const hosts=(env.PS_ALLOWED_HOSTS??("127.0.0.1:"+port+",localhost:"+port)).split(",").map(s=>s.trim().toLowerCase());
  if(!hosts.length||hosts.some(h=>!/^[-a-z0-9.]+(?::[0-9]{1,5})?$/.test(h)))throw new Error("Invalid allowed hosts");
  const clients=JSON.parse(env.PS_CLIENTS_JSON??"[]");
  if(!Array.isArray(clients)||clients.length>100)throw new Error("Invalid clients");
  const ids=new Set(),digests=new Set();
  for(const c of clients){
    if(!c||typeof c!=="object"||!/^[-a-zA-Z0-9_]{1,64}$/.test(c.id??"")||!(/^[a-f0-9]{64}$/.test(c.sha256??""))||ids.has(c.id)||digests.has(c.sha256)||!Array.isArray(c.scopes)||!c.scopes.length||c.scopes.some(s=>!["input","output"].includes(s)))throw new Error("Invalid client configuration");
    ids.add(c.id);digests.add(c.sha256);
  }
  const markers=JSON.parse(env.PS_PROTECTED_MARKERS_JSON??"[]");
  const policy=env.PS_POLICY??"strict";
  inspect("",{policy,protectedMarkers:markers});
  if(bind==="0.0.0.0"&&(!clients.length||env.PS_BEHIND_TLS_PROXY!=="true"||!env.PS_ALLOWED_HOSTS))throw new Error("Non-loopback requires configured clients, allowed hosts and TLS proxy acknowledgement");
  return {port,bind,hosts,clients,markers,policy,rate:bounded(env.PS_RATE_PER_MINUTE??60,1,600,"PS_RATE_PER_MINUTE"),maxConcurrent:bounded(env.PS_MAX_CONCURRENT??16,1,128,"PS_MAX_CONCURRENT")};
}
export function createServer(config,{audit=()=>{},now=Date.now}={}){
  const buckets=new Map();
  let active=0;
  const maxBytes=128*1024;
  const root=new URL("./",import.meta.url);
  const server=http.createServer(async(req,res)=>{
    const requestId=randomUUID(),started=now();
    let clientId=null,decision=null,ruleIds=[];
    const endpoint=req.url==="/v1/inspect/input"?"input":req.url==="/v1/inspect/output"?"output":null;
    const finish=(status,body,extra={})=>{
      if(res.destroyed||res.writableEnded)return;
      res.writeHead(status,{"Content-Type":"application/json; charset=utf-8","X-Request-Id":requestId,...HEADERS,...extra});
      res.end(JSON.stringify(body));
      if(endpoint)try{audit({requestId,clientId,direction:endpoint,status,decision,ruleIds,durationMs:Math.max(0,now()-started)});}catch{/* audit failures cannot release payloads */}
    };
    const reject=(status,error,extra={})=>finish(status,{error,requestId},extra);
    if(!config.hosts.includes((req.headers.host??"").toLowerCase()))return reject(403,"Host not allowed");
    if(req.url==="/healthz"&&req.method==="GET")return finish(200,{status:"ok",apiEnabled:config.clients.length>0});
    if(endpoint){
      if(req.method!=="POST")return reject(405,"Method not allowed",{Allow:"POST"});
      if(req.headers.origin||req.headers["sec-fetch-site"])return reject(403,"Browser API requests not supported");
      if(!config.clients.length)return reject(503,"Inspection API not configured");
      const auth=/^Bearer ([A-Za-z0-9_-]{32,256})$/.exec(req.headers.authorization??"");
      if(!auth)return reject(401,"Authentication required",{"WWW-Authenticate":"Bearer"});
      const digest=hash(auth[1]);
      const client=config.clients.find(c=>timingSafeEqual(digest,Buffer.from(c.sha256,"hex")));
      if(!client)return reject(401,"Authentication required",{"WWW-Authenticate":"Bearer"});
      clientId=client.id;
      if(!client.scopes.includes(endpoint))return reject(403,"Scope denied");
      const t=now(),old=buckets.get(client.id);
      const b=!old||t-old.start>=60000?{start:t,count:0}:old;
      if(b.count>=config.rate)return reject(429,"Rate limit exceeded",{"Retry-After":String(Math.max(1,Math.ceil((60000-(t-b.start))/1000)))});
      b.count++;buckets.set(client.id,b);
      if(active>=config.maxConcurrent)return reject(503,"Inspection capacity reached",{"Retry-After":"1"});
      if(!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(req.headers["content-type"]??"")||req.headers["content-encoding"])return reject(415,"Uncompressed UTF-8 JSON required");
      if(Number(req.headers["content-length"]??0)>maxBytes){res.setHeader("Connection","close");return reject(413,"Request too large");}
      active++;
      try{
        const chunks=[];let size=0;
        for await(const chunk of req){
          size+=chunk.length;
          if(size>maxBytes){res.setHeader("Connection","close");reject(413,"Request too large");return;}
          chunks.push(chunk);
        }
        let payload;
        try{payload=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(Buffer.concat(chunks)));}catch{return reject(400,"Invalid JSON");}
        if(!payload||typeof payload!=="object"||Array.isArray(payload)||Object.keys(payload).some(k=>!["text","source"].includes(k))||typeof payload.text!=="string"||!payload.text.trim()||!["user","retrieved","tool"].includes(payload.source??"user"))return reject(400,"Invalid inspection payload");
        let result;
        try{result=inspect(payload.text,{direction:endpoint,source:payload.source??"user",protectedMarkers:config.markers,policy:config.policy});}catch(e){return reject(e instanceof TypeError?400:500,"Inspection failed; do not forward");}
        decision=result.decision;ruleIds=result.findings.map(f=>f.id);
        return finish(200,{requestId,...result});
      }catch{return reject(400,"Request interrupted; do not forward");}
      finally{active--;}
    }
    if(req.method!=="GET")return reject(405,"Method not allowed",{Allow:"GET"});
    const path=ASSETS.get(req.url);
    if(!path)return reject(404,"Not found");
    try{const body=await readFile(new URL(path,root));res.writeHead(200,{"Content-Type":MIME[path.split(".").at(-1)],...HEADERS});res.end(body);}
    catch{return reject(500,"Asset unavailable");}
  });
  server.requestTimeout=10000;server.headersTimeout=5000;server.keepAliveTimeout=2000;server.maxHeadersCount=50;server.maxConnections=256;
  server.setTimeout(10000,socket=>socket.destroy());
  return server;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  const config=loadConfig();
  const server=createServer(config,{audit:e=>process.stdout.write(JSON.stringify(e)+"\n")});
  server.listen(config.port,config.bind,()=>console.log("PromptShield listening on "+config.bind+":"+config.port));
  for(const signal of ["SIGTERM","SIGINT"])process.once(signal,()=>{server.close(()=>process.exit(0));setTimeout(()=>process.exit(1),10000).unref();});
}
