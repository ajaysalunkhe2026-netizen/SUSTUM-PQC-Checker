import type {Dependency,Diagnostic,Finding} from "./model";
type Rule={re:RegExp;algorithm:string;family:string;primitive:Finding["primitive"];purpose:string;vulnerable:boolean|null;confidence:Finding["confidence"]};
const rules:Rule[]=[
 {re:/\b(?:KeyPairGenerator\s*\.\s*getInstance\s*\(\s*["']RSA|generateKeyPair(?:Sync)?\s*\(\s*["']rsa|rsa\s*\.\s*(?:GenerateKey|generate_private_key)\s*\(|RSA_generate_key_ex\s*\()/g,algorithm:"RSA",family:"RSA",primitive:"unknown",purpose:"RSA key generation (actual use undetermined)",vulnerable:true,confidence:"high"},
 {re:/\b(?:Signature\s*\.\s*getInstance\s*\(\s*["'][^"']*ECDSA|ecdsa\s*\.\s*Sign|ec\s*\.\s*ECDSA\s*\()/g,algorithm:"ECDSA",family:"ECDSA",primitive:"signature",purpose:"Digital signature",vulnerable:true,confidence:"medium"},
 {re:/\bcreateSign\s*\(/g,algorithm:"Signature operation",family:"unknown",primitive:"signature",purpose:"Signature operation (algorithm undetermined)",vulnerable:null,confidence:"low"},
 {re:/\b(?:KeyAgreement\s*\.\s*getInstance\s*\(\s*["']ECDH|createECDH\s*\(|ecdh\s*\.\s*X(?:25519|448)\s*\(|ec\s*\.\s*ECDH\s*\()/g,algorithm:"ECDH",family:"ECDH",primitive:"key-agree",purpose:"Key establishment",vulnerable:true,confidence:"medium"},
 {re:/\b(?:MessageDigest\s*\.\s*getInstance\s*\(\s*["']SHA-?1|sha1\s*\.\s*New\s*\(|hashlib\s*\.\s*sha1\s*\(|hashes\s*\.\s*SHA1\s*\(|createHash\s*\(\s*["']sha-?1/g,algorithm:"SHA-1",family:"SHA",primitive:"hash",purpose:"Hash",vulnerable:null,confidence:"medium"}
];
const TICK=String.fromCharCode(96);
export function maskComments(source:string,ext:string):string{
 const python=ext===".py",chars=source.split("");let i=0;
 let state:"code"|"single"|"double"|"template"|"triple-single"|"triple-double"|"line"|"block"="code";
 while(i<chars.length){const c=chars[i],n=chars[i+1];
  if(state==="line"){if(c==="\n")state="code";else chars[i]=" ";i++;continue;}
  if(state==="block"){if(c==="*"&&n==="/"){chars[i]=" ";chars[i+1]=" ";i+=2;state="code";}else{if(c!=="\n")chars[i]=" ";i++;}continue;}
  if(state==="single"||state==="double"||state==="template"){const end=state==="single"?"'":state==="double"?'"':TICK;if(c==="\\"){i+=2;continue;}if(c===end)state="code";i++;continue;}
  if(state==="triple-single"||state==="triple-double"){const end=state==="triple-single"?"'''":'"""';if(source.slice(i,i+3)===end){state="code";i+=3;continue;}if(c==="\\"){i+=2;continue;}i++;continue;}
  if(python&&source.slice(i,i+3)==="'''"){state="triple-single";i+=3;continue;}if(python&&source.slice(i,i+3)==='"""'){state="triple-double";i+=3;continue;}
  if(c==="'"){state="single";i++;continue;}if(c==='"'){state="double";i++;continue;}if(!python&&c===TICK){state="template";i++;continue;}
  if(python&&c==="#"){state="line";chars[i]=" ";i++;continue;}if(!python&&c==="/"&&n==="/"){state="line";chars[i]=" ";chars[i+1]=" ";i+=2;continue;}if(!python&&c==="/"&&n==="*"){state="block";chars[i]=" ";chars[i+1]=" ";i+=2;continue;}i++;
 }
 return chars.join("");
}
function isCodeOffset(source:string,offset:number,ext:string):boolean{
 const python=ext===".py";let i=0,state:"code"|"single"|"double"|"template"|"triple-single"|"triple-double"="code";
 while(i<offset){const c=source[i];
  if(state==="single"||state==="double"||state==="template"){const end=state==="single"?"'":state==="double"?'"':TICK;if(c==="\\"){i+=2;continue;}if(c===end)state="code";i++;continue;}
  if(state==="triple-single"||state==="triple-double"){const end=state==="triple-single"?"'''":'"""';if(source.slice(i,i+3)===end){state="code";i+=3;continue;}if(c==="\\"){i+=2;continue;}i++;continue;}
  if(python&&source.slice(i,i+3)==="'''"){state="triple-single";i+=3;continue;}if(python&&source.slice(i,i+3)==='"""'){state="triple-double";i+=3;continue;}
  if(c==="'"){state="single";i++;continue;}if(c==='"'){state="double";i++;continue;}if(!python&&c===TICK){state="template";i++;continue;}i++;
 }
 return state==="code";
}
export function parseManifest(path:string,s:string,deps:Dependency[],diag:Diagnostic[]):void{
 const name=path.split("/").pop()||"";
 if(name==="package.json"){try{const j=JSON.parse(s);if(!j||typeof j!=="object"||Array.isArray(j))throw new Error("Expected JSON object");for(const [group,scope] of [["dependencies","runtime"],["devDependencies","development"],["optionalDependencies","optional"],["peerDependencies","peer"]] as const){const obj=j[group];if(obj&&typeof obj==="object"&&!Array.isArray(obj))for(const [n,v] of Object.entries(obj)){const spec=typeof v==="string"?v.trim():"";const exact=/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(spec);deps.push({name:n,version:exact?spec:"unspecified",...(spec&&!exact?{versionConstraint:spec}:{}),ecosystem:"npm",scope,source:path,evidence:"declared"});}}}catch{diag.push({code:"MANIFEST_JSON",message:"Invalid package.json; dependency inventory is incomplete.",file:path});}}
 if(name==="requirements.txt")for(const raw of s.split(/\r?\n/)){let line=raw.trim();if(!line||line.startsWith("#"))continue;line=line.replace(/\s+#.*$/,"").trim();if(line.startsWith("-")){diag.push({code:"REQUIREMENTS_OPTION",message:"pip option or include directive is not resolved by this lightweight manifest parser.",file:path});continue;}const markerAt=line.indexOf(";");if(markerAt>=0)line=line.slice(0,markerAt).trim();const m=/^([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]+\])?\s*(.*)$/.exec(line);if(!m){diag.push({code:"REQUIREMENTS_LINE",message:"Unsupported requirements entry; dependency inventory may be incomplete.",file:path});continue;}const tail=m[2].trim();let version="unspecified",versionConstraint="";if(tail.startsWith("@"))versionConstraint="direct-reference "+tail.slice(1).trim();else if(tail){if(!/^(?:===|==|~=|!=|>=|<=|>|<)\s*[^\s,]+(?:\s*,\s*(?:===|==|~=|!=|>=|<=|>|<)\s*[^\s,]+)*$/.test(tail)){diag.push({code:"REQUIREMENTS_SPECIFIER",message:"Unrecognized version specifier; entry retained without a resolved version.",file:path});versionConstraint=tail;}else{versionConstraint=tail;const pinned=/^(?:===|==)\s*([0-9][A-Za-z0-9.!+_-]*)$/.exec(tail);if(pinned)version=pinned[1];}}deps.push({name:m[1],version,...(versionConstraint?{versionConstraint}:{}),ecosystem:"pypi",scope:"runtime",source:path,evidence:"declared"});}
 if(name==="go.mod")for(const m of s.matchAll(/^\s*([A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)+)\s+(v[0-9][\w.+-]*)/gm))deps.push({name:m[1],version:m[2],ecosystem:"go",scope:"runtime-or-unknown",source:path,evidence:"declared"});
}
export function scanSource(path:string,s:string,out:Finding[]):void{
 const dot=path.lastIndexOf("."),ext=dot>=0?path.slice(dot).toLowerCase():"",masked=maskComments(s,ext);
 for(const rule of rules){rule.re.lastIndex=0;let m:RegExpExecArray|null;while((m=rule.re.exec(masked))!==null){if(!isCodeOffset(masked,m.index,ext))continue;const line=masked.slice(0,m.index).split("\n").length,id=path+":"+line+":"+rule.algorithm+":"+rule.purpose;if(out.some(x=>x.id===id))continue;
  const recommendation=rule.algorithm==="RSA"?"Review actual usage, key sizes and protocol context before selecting a PQC replacement.":rule.algorithm==="ECDSA"?"Assess ML-DSA with protocol, certificate and interoperability constraints.":rule.algorithm==="ECDH"?"Assess ML-KEM and an approved hybrid transition design.":rule.algorithm==="SHA-1"?"Determine whether SHA-1 is used for security-sensitive signatures, certificates, integrity or only legacy/non-security purposes.":"Identify the concrete signing algorithm and call path before classifying this indicator.";
  out.push({id,algorithm:rule.algorithm,family:rule.family,primitive:rule.primitive,purpose:rule.purpose,file:path,line,evidence:m[0].slice(0,240),confidence:rule.confidence,quantumVulnerable:rule.vulnerable,recommendation});
 }}
}
