import {randomBytes,createHash} from "node:crypto";
const id=process.argv[2]??"integration";
if(!/^[-a-zA-Z0-9_]{1,64}$/.test(id))throw new Error("Invalid client id");
const token=randomBytes(32).toString("base64url");
console.log("Save this token in a trusted secret manager. It is shown once:");
console.log(token);
console.log("PS_CLIENTS_JSON="+JSON.stringify([{id,sha256:createHash("sha256").update(token).digest("hex"),scopes:["input","output"]}]));
