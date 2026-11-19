/// <reference lib="webworker" />
import JSZip from "jszip";
import type {Dependency,Diagnostic,Finding,ScanResult} from "./model";
import {parseManifest,scanSource} from "./scanner-core";
type ScanMessage={type:"scan";buffer:ArrayBuffer};
type ZipEntry=JSZip.JSZipObject & {unsafeOriginalName?:string;_data?:{uncompressedSize?:number;compressedSize?:number}};
const worker=self as unknown as DedicatedWorkerGlobalScope;
const MAX_ARCHIVE=100*1024*1024,MAX_ENTRIES=5000,MAX_CANDIDATES=2000,MAX_FILE=2*1024*1024,MAX_TOTAL=50*1024*1024,MAX_SCAN_MS=30000,MAX_RATIO=200;
const sourceExt=new Set([".py",".js",".jsx",".ts",".tsx",".java",".go",".c",".h",".cpp",".cc"]);
const manifests=new Set(["package.json","requirements.txt","go.mod"]);
worker.onmessage=async(event:MessageEvent<ScanMessage>)=>{
 if(event.data.type!=="scan")return;
 const started=performance.now(),findings:Finding[]=[],dependencies:Dependency[]=[],diagnostics:Diagnostic[]=[];
 let filesScanned=0,bytesScanned=0,candidates=0;
 try{
  if(!(event.data.buffer instanceof ArrayBuffer)||event.data.buffer.byteLength===0)throw new Error("The selected archive is empty or invalid.");
  if(event.data.buffer.byteLength>MAX_ARCHIVE)throw new Error("Archive exceeds 100 MiB.");
  const zip=await JSZip.loadAsync(event.data.buffer,{checkCRC32:false}),allEntries=Object.values(zip.files) as ZipEntry[];
  if(allEntries.length>MAX_ENTRIES)throw new Error("Archive exceeds 5,000 total entries.");
  const seen=new Set<string>();
  for(const entry of allEntries){
   if(entry.dir)continue;
   if(performance.now()-started>MAX_SCAN_MS)throw new Error("Scan exceeded the 30 second browser time budget.");
   const raw=entry.unsafeOriginalName??entry.name,path=raw.replace(/\\/g,"/"),parts=path.split("/");
   if(path.startsWith("/")||/^[a-zA-Z]:/.test(path)||parts.includes("..")||path.includes("\0")||parts.some(p=>p==="")){diagnostics.push({code:"UNSAFE_PATH",message:"Absolute, traversal, or malformed archive path rejected.",file:path.slice(0,240)});continue;}
   const normalized=parts.join("/");
   if(seen.has(normalized)){diagnostics.push({code:"DUPLICATE_PATH",message:"Duplicate normalized archive path rejected.",file:normalized.slice(0,240)});continue;}
   seen.add(normalized);
   const unix=entry.unixPermissions;
   if(typeof unix==="number"&&((unix>>>12)&0xf)===0xa){diagnostics.push({code:"SYMLINK",message:"Symbolic-link entry rejected.",file:normalized.slice(0,240)});continue;}
   const base=parts.at(-1)||"",ext=base.includes(".")?base.slice(base.lastIndexOf(".")).toLowerCase():"";
   if(!sourceExt.has(ext)&&!manifests.has(base))continue;
   candidates++;if(candidates>MAX_CANDIDATES)throw new Error("Archive exceeds 2,000 candidate source and manifest files.");
   const declared=entry._data?.uncompressedSize,compressed=entry._data?.compressedSize;
   if(typeof declared==="number"&&declared>MAX_FILE){diagnostics.push({code:"FILE_LIMIT",message:"Declared uncompressed file size exceeds 2 MiB; entry skipped before extraction.",file:normalized.slice(0,240)});continue;}
   if(typeof declared==="number"&&typeof compressed==="number"&&declared>1024*1024&&compressed>0&&declared/compressed>MAX_RATIO){diagnostics.push({code:"COMPRESSION_RATIO",message:"Suspicious compression ratio exceeds 200:1; entry skipped before extraction.",file:normalized.slice(0,240)});continue;}
   if(typeof declared==="number"&&bytesScanned+declared>MAX_TOTAL)throw new Error("Candidate files exceed 50 MiB aggregate declared extracted data.");
   const bytes=await entry.async("uint8array");
   if(bytes.byteLength>MAX_FILE){diagnostics.push({code:"FILE_LIMIT",message:"Actual extracted file size exceeds 2 MiB; entry skipped.",file:normalized.slice(0,240)});continue;}
   if(typeof declared==="number"&&bytes.byteLength!==declared){diagnostics.push({code:"SIZE_MISMATCH",message:"Extracted size differs from ZIP metadata; entry skipped.",file:normalized.slice(0,240)});continue;}
   bytesScanned+=bytes.byteLength;
   if(bytesScanned>MAX_TOTAL)throw new Error("Candidate files exceed 50 MiB aggregate extracted data.");
   const source=new TextDecoder("utf-8",{fatal:false}).decode(bytes);filesScanned++;
   if(manifests.has(base))parseManifest(normalized,source,dependencies,diagnostics);
   if(sourceExt.has(ext))scanSource(normalized,source,findings);
  }
  const result:ScanResult={findings,dependencies,diagnostics,filesScanned,bytesScanned,durationMs:Math.round(performance.now()-started)};
  worker.postMessage({type:"complete",result});
 }catch(error){worker.postMessage({type:"error",message:error instanceof Error?error.message:"Unknown scan failure"});}
};
export {};
