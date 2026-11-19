import type {Dependency,Diagnostic,Finding} from "./model";
const rules:{re:RegExp;algorithm:string;family:string;primitive:Finding["primitive"];purpose:string;vulnerable:boolean|null;confidence:Finding["confidence"]}[]=[
 {re:/\b(?:KeyPairGenerator\s*\.\s*getInstance\s*\(\s*["']RSA|generateKeyPair(?:Sync)?\s*\(\s*["']rsa|rsa\s*\.\s*GenerateKey\s*\(|RSA_generate_key_ex\s*\()/g,algorithm:"RSA",family:"RSA",primitive:"unknown",purpose:"RSA key generation (actual use undetermined)",vulnerable:true,confidence:"high"},
 {re:/\b(?:Signature\s*\.\s*getInstance\s*\(\s*["'][^"']*ECDSA|ecdsa\s*\.\s*Sign)/g,algorithm:"ECDSA",family:"ECDSA",primitive:"signature",purpose:"Digital signature",vulnerable:true,confidence:"medium"},
 {re:/\bcreateSign\s*\(/g,algorithm:"Signature operation",family:"unknown",primitive:"signature",purpose:"Signature operation (algorithm undetermined)",vulnerable:null,confidence:"low"},
 {re:/\b(?:KeyAgreement\s*\.\s*getInstance\s*\(\s*["']ECDH|createECDH\s*\(|ecdh\s*\.\s*X(?:25519|448)\s*\()/g,algorithm:"ECDH",family:"ECDH",primitive:"key-agree",purpose:"Key establishment",vulnerable:true,confidence:"medium"},
 {re:/\b(?:MessageDigest\s*\.\s*getInstance\s*\(\s*["']SHA-?1|sha1\s*\.\s*New\s*\()/g,algorithm:"SHA-1",family:"SHA",primitive:"hash",purpose:"Hash",vulnerable:false,confidence:"medium"}
];
export function maskComments(s:string,ext:string):string{
 if(ext===".py")return s.replace(/(^|\s)#.*$/gm,m=>m.replace(/[^\n]/g," "));
 return s.replace(/\/\*[\s\S]*?\*\//g,m=>m.replace(/[^\n]/g," ")).replace(/(^|\s)\/\/[^\n]*/gm,m=>m.replace(/[^\n]/g," "));
}
export function parseManifest(path:string,s:string,deps:Dependency[],diag:Diagnostic[]):void{
 const name=path.split("/").pop()||"";
 if(name==="package.json"){try{const j=JSON.parse(s);if(!j||typeof j!=="object"||Array.isArray(j))throw new Error("Expected JSON object");for(const [group,scope] of [["dependencies","runtime"],["devDependencies","development"],["optionalDependencies","optional"]] as const){const obj=j[group];if(obj&&typeof obj==="object"&&!Array.isArray(obj))for(const [n,v] of Object.entries(obj))deps.push({name:n,version:typeof v==="string"?v:"unspecified",ecosystem:"npm",scope,source:path,evidence:"declared"});}}catch{diag.push({code:"MANIFEST_JSON",message:"Invalid package.json; dependency inventory is incomplete.",file:path});}}
 if(name==="requirements.txt")for(const raw of s.split(/\r?\n/)){const line=raw.trim();if(!line||line.startsWith("#"))continue;const m=/^([A-Za-z0-9_.-]+)\s*(?:==|>=|~=|<=|>|<)?\s*([^;\s]*)/.exec(line);if(m)deps.push({name:m[1],version:m[2]||"unspecified",ecosystem:"pypi",scope:"runtime",source:path,evidence:"declared"});}
 if(name==="go.mod")for(const m of s.matchAll(/^\s*([\w.-]+(?:\/[\w.-]+)+)\s+(v[\w.+-]+)/gm))deps.push({name:m[1],version:m[2],ecosystem:"go",scope:"runtime-or-unknown",source:path,evidence:"declared"});
}
export function scanSource(path:string,s:string,out:Finding[]):void{
 const ext=path.slice(path.lastIndexOf(".")).toLowerCase(),masked=maskComments(s,ext);
 for(const rule of rules){rule.re.lastIndex=0;let m:RegExpExecArray|null;while((m=rule.re.exec(masked))!==null){const line=masked.slice(0,m.index).split("\n").length,id=path+":"+line+":"+rule.algorithm+":"+rule.purpose;if(out.some(x=>x.id===id))continue;out.push({id,algorithm:rule.algorithm,family:rule.family,primitive:rule.primitive,purpose:rule.purpose,file:path,line,evidence:m[0].slice(0,240),confidence:rule.confidence,quantumVulnerable:rule.vulnerable,recommendation:rule.algorithm==="RSA"?"Review actual usage before choosing a PQC replacement.":rule.algorithm==="ECDSA"?"Evaluate ML-DSA with protocol and interoperability constraints.":rule.algorithm==="ECDH"?"Evaluate ML-KEM and approved hybrid transition design.":"Review hash usage and protocol context."});}}
}
