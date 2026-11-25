import http from "node:http";
import {readFile} from "node:fs/promises";
import {inspect} from "./src/engine.mjs";
const port=Number(process.env.PORT??3000);
if(!Number.isInteger(port)||port<1||port>65535)throw new Error("Invalid port");
const root=new URL("./",import.meta.url);
const assets=new Map([["/","index.html"],["/index.html","index.html"],["/src/style.css","src/style.css"],["/src/app.mjs","src/app.mjs"],["/src/engine.mjs","src/engine.mjs"],["/src/cases.mjs","src/cases.mjs"]]);
const mime={html:"text/html; charset=utf-8",css:"text/css; charset=utf-8",mjs:"text/javascript; charset=utf-8"};
const headers={"Cache-Control":"no-store","X-Content-Type-Options":"nosniff","Referrer-Policy":"no-referrer","X-Frame-Options":"DENY","Content-Security-Policy":"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"};
function json(res,status,body){res.writeHead(status,{"Content-Type":"application/json; charset=utf-8",...headers});res.end(JSON.stringify(body));}
const server=http.createServer(async(req,res)=>{
  const host=req.headers.host;
  if(host!==("127.0.0.1:"+port)&&host!==("localhost:"+port))return json(res,403,{error:"Local host required."});
  if(req.method==="POST"&&req.url==="/api/inspect"){
    if(req.headers.origin&&req.headers.origin!==("http://"+host))return json(res,403,{error:"Cross-origin requests denied."});
    if(!/^application\/json(?:\s*;|$)/i.test(req.headers["content-type"]??""))return json(res,415,{error:"JSON required."});
    const max=150000;let size=0;const parts=[];
    try{
      for await(const chunk of req){size+=chunk.length;if(size>max){json(res,413,{error:"Request too large."});return;}parts.push(chunk);}
      const payload=JSON.parse(Buffer.concat(parts).toString("utf8"));
      if(!payload||typeof payload!=="object"||Array.isArray(payload))throw new TypeError();
      const {text,options={}}=payload;
      if(!options||typeof options!=="object"||Array.isArray(options))throw new TypeError();
      return json(res,200,inspect(text,options));
    }catch{return json(res,400,{error:"Invalid inspection request."});}
  }
  if(req.method!=="GET")return json(res,405,{error:"Method not allowed."});
  const path=assets.get(req.url);
  if(!path)return json(res,404,{error:"Not found."});
  try{const body=await readFile(new URL(path,root));res.writeHead(200,{"Content-Type":mime[path.split(".").at(-1)],...headers});res.end(body);}
  catch{return json(res,500,{error:"Asset unavailable."});}
});
server.requestTimeout=10000;server.headersTimeout=5000;server.maxHeadersCount=50;
server.listen(port,"127.0.0.1",()=>console.log("PromptShield local lab: http://127.0.0.1:"+port));
