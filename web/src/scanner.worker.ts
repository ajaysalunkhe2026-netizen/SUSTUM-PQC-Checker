/// <reference lib="webworker" />
import JSZip from "jszip";
import type {Dependency,Diagnostic,Finding,ScanResult} from "./model";
type ScanMessage={type:"scan";buffer:ArrayBuffer};
const worker=self as unknown as DedicatedWorkerGlobalScope;
const MAX_ARCHIVE=100*1024*1024,MAX_ENTRIES=5000,MAX_FILE=2*1024*1024,MAX_TOTAL=50*1024*1024,MAX_SCAN_MS=30000;
const rules:{re:RegExp;algorithm:string;family:string;primitive:Finding["primitive"];purpose:string;vulnerable:boolean|null;confidence:Finding["confidence"]}[]=[
 {re:/\b(?:KeyPairGenerator\s*\.\s*getInstance\s*\(\s*["']RSA|generateKeyPair(?:Sync)?\s*\(\s*["']rsa|rsa\s*\.\s*GenerateKey\s*\(|RSA_generate_key_ex\s*\()/g,algorithm:"RSA",family:"RSA",primitive:"pke",purpose:"Asymmetric key generation/use",vulnerable:true,confidence:"high"},
 {re:/\b(?:Signature\s*\.\s*getInstance\s*\(\s*["'][^"']*ECDSA|createSign\s*\(|ecdsa\s*\.\s*Sign)/g,algorithm:"ECDSA",family:"ECDSA",primitive:"signature",purpose:"Digital signature",vulnerable:true,confidence:"medium"},
 {re:/\b(?:KeyAgreement\s*\.\s*getInstance\s*\(\s*["']ECDH|createECDH\s*\(|ecdh\s*\.\s*X(?:25519|448)\s*\()/g,algorithm:"ECDH",family:"ECDH",primitive:"key-agree",purpose:"Key establishment",vulnerable:true,confidence:"medium"},
 {re:/\b(?:MessageDigest\s*\.\s*getInstance\s*\(\s*["']SHA-?1|sha1\s*\.\s*New\s*\()/g,algorithm:"SHA-1",family:"SHA",primitive:"hash",purpose:"Hash",vulnerable:false,confidence:"medium"}
];
function maskComments(s:string,ext:string):string{
 if(ext===".py")return s.replace(/(^|\s)#.*$/gm,m=>m.replace(/[^\n]/g," "));
 return s.replace(/\/\*[\s\S]*?\*\//g,m=>m.replace(/[^\n]/g," ")).replace(/(^|\s)\/\/[^\n]*/gm,m=>m.replace(/[^\n]/g," "));
}
function parseManifest(path:string,s:string,deps:Dependency[],diag:Diagnostic[]){
 const name=path.split("/").pop()||"";
 if(name==="package.json"){try{const j=JSON.parse(s);for(const [group,scope] of [["dependencies","runtime"],["devDependencies","development"],["optionalDependencies","optional"]] as const){const obj=j[group];if(obj&&typeof obj==="object")for(const [n,v] of Object.entries(obj))deps.push({name:n,version:String(v),ecosystem:"npm",scope,source:path,evidence:"declared"});}}catch{diag.push({code:"MANIFEST_JSON",message:"Invalid package.json; dependency inventory is incomplete.",file:path});}}
 if(name==="requirements.txt")for(const raw of s.split(/\r?\n/)){const line=raw.trim();if(!line||line.startsWith("#"))continue;const m=/^([A-Za-z0-9_.-]+)\s*(?:==|>=|~=|<=|>|<)?\s*([^;\s]*)/.exec(line);if(m)deps.push({name:m[1],version:m[2]||"unspecified",ecosystem:"pypi",scope:"runtime",source:path,evidence:"declared"});}
 if(name==="go.mod")for(const m of s.matchAll(/^\s*([\w.-]+(?:\/[\w.-]+)+)\s+(v[\w.+-]+)/gm))deps.push({name:m[1],version:m[2],ecosystem:"go",scope:"runtime-or-unknown",source:path,evidence:"declared"});
}
function scanSource(path:string,s:string,out:Finding[]){
 const ext=path.slice(path.lastIndexOf(".")).toLowerCase(),masked=maskComments(s,ext);
 for(const rule of rules){rule.re.lastIndex=0;let m:RegExpExecArray|null;while((m=rule.re.exec(masked))!==null){const line=masked.slice(0,m.index).split("\n").length,id=path+":"+line+":"+rule.algorithm+":"+rule.purpose;if(out.some(x=>x.id===id))continue;out.push({id,algorithm:rule.algorithm,family:rule.family,primitive:rule.primitive,purpose:rule.purpose,file:path,line,evidence:m[0].slice(0,240),confidence:rule.confidence,quantumVulnerable:rule.vulnerable,recommendation:rule.algorithm==="RSA"?"Review actual usage before choosing a PQC replacement.":rule.algorithm==="ECDSA"?"Evaluate ML-DSA with protocol and interoperability constraints.":rule.algorithm==="ECDH"?"Evaluate ML-KEM and approved hybrid transition design.":"Review hash usage and protocol context."});}}
}
worker.onmessage=async(event:MessageEvent<ScanMessage>)=>{
 if(event.data.type!=="scan")return;const started=performance.now(),findings:Finding[]=[],dependencies:Dependency[]=[],diagnostics:Diagnostic[]=[];let filesScanned=0,bytesScanned=0;
 try{
  if(event.data.buffer.byteLength>MAX_ARCHIVE)throw new Error("Archive exceeds 100 MiB.");
  const zip=await JSZip.loadAsync(event.data.buffer);const allEntries=Object.values(zip.files);
  if(allEntries.length>MAX_ENTRIES)throw new Error("Archive exceeds 5,000 total entries.");
  const entries=allEntries.filter(x=>!x.dir);
  for(const entry of entries){
   if(performance.now()-started>MAX_SCAN_MS)throw new Error("Scan exceeded the 30 second browser time budget.");
   const raw=(entry as JSZip.JSZipObject & {unsafeOriginalName?:string}).unsafeOriginalName??entry.name;
   const path=raw.replace(/\\/g,"/"),parts=path.split("/");
   if(path.startsWith("/")||parts.includes("..")||path.includes("\0")){diagnostics.push({code:"UNSAFE_PATH",message:"Unsafe archive path rejected.",file:path});continue;}
   const unix=entry.unixPermissions;if(typeof unix==="number"&&((unix>>>12)&0xf)===0xa){diagnostics.push({code:"SYMLINK",message:"Symbolic-link entry rejected.",file:path});continue;}
   const base=parts.at(-1)||"",ext=base.includes(".")?base.slice(base.lastIndexOf(".")).toLowerCase():"";
   const sourceExt=[".py",".js",".jsx",".ts",".tsx",".java",".go",".c",".h",".cpp",".cc"];
   const manifests=["package.json","requirements.txt","go.mod"];
   if(!sourceExt.includes(ext)&&!manifests.includes(base))continue;
   const bytes=await entry.async("uint8array");if(bytes.byteLength>MAX_FILE){diagnostics.push({code:"FILE_LIMIT",message:"File exceeds 2 MiB and was skipped.",file:path});continue;}
   bytesScanned+=bytes.byteLength;if(bytesScanned>MAX_TOTAL)throw new Error("Candidate files exceed 50 MiB aggregate extracted data.");
   const source=new TextDecoder("utf-8").decode(bytes);filesScanned++;
   if(manifests.includes(base))parseManifest(path,source,dependencies,diagnostics);
   if(sourceExt.includes(ext))scanSource(path,source,findings);
  }
  const result:ScanResult={findings,dependencies,diagnostics,filesScanned,bytesScanned,durationMs:Math.round(performance.now()-started)};
  worker.postMessage({type:"complete",result});
 }catch(error){worker.postMessage({type:"error",message:error instanceof Error?error.message:"Unknown scan failure"});}
};
export {};
