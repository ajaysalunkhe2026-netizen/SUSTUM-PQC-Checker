/// <reference lib="webworker" />
import JSZip from "jszip";
import type {Dependency,Diagnostic,Finding,ScanResult} from "./model";
import {parseManifest,scanSource} from "./scanner-core";
type ScanMessage={type:"scan";buffer:ArrayBuffer};
const worker=self as unknown as DedicatedWorkerGlobalScope;
const MAX_ARCHIVE=100*1024*1024,MAX_ENTRIES=5000,MAX_FILE=2*1024*1024,MAX_TOTAL=50*1024*1024,MAX_SCAN_MS=30000;
worker.onmessage=async(event:MessageEvent<ScanMessage>)=>{
 if(event.data.type!=="scan")return;
 const started=performance.now(),findings:Finding[]=[],dependencies:Dependency[]=[],diagnostics:Diagnostic[]=[];
 let filesScanned=0,bytesScanned=0;
 try{
  if(event.data.buffer.byteLength>MAX_ARCHIVE)throw new Error("Archive exceeds 100 MiB.");
  const zip=await JSZip.loadAsync(event.data.buffer),allEntries=Object.values(zip.files);
  if(allEntries.length>MAX_ENTRIES)throw new Error("Archive exceeds 5,000 total entries.");
  for(const entry of allEntries){
   if(entry.dir)continue;
   if(performance.now()-started>MAX_SCAN_MS)throw new Error("Scan exceeded the 30 second browser time budget.");
   const raw=(entry as JSZip.JSZipObject & {unsafeOriginalName?:string}).unsafeOriginalName??entry.name;
   const path=raw.replace(/\\/g,"/"),parts=path.split("/");
   if(path.startsWith("/")||parts.includes("..")||path.includes("\0")){diagnostics.push({code:"UNSAFE_PATH",message:"Unsafe archive path rejected.",file:path});continue;}
   const unix=entry.unixPermissions;
   if(typeof unix==="number"&&((unix>>>12)&0xf)===0xa){diagnostics.push({code:"SYMLINK",message:"Symbolic-link entry rejected.",file:path});continue;}
   const base=parts.at(-1)||"",ext=base.includes(".")?base.slice(base.lastIndexOf(".")).toLowerCase():"";
   const sourceExt=[".py",".js",".jsx",".ts",".tsx",".java",".go",".c",".h",".cpp",".cc"];
   const manifests=["package.json","requirements.txt","go.mod"];
   if(!sourceExt.includes(ext)&&!manifests.includes(base))continue;
   const bytes=await entry.async("uint8array");
   if(bytes.byteLength>MAX_FILE){diagnostics.push({code:"FILE_LIMIT",message:"File exceeds 2 MiB and was skipped.",file:path});continue;}
   bytesScanned+=bytes.byteLength;
   if(bytesScanned>MAX_TOTAL)throw new Error("Candidate files exceed 50 MiB aggregate extracted data.");
   const source=new TextDecoder("utf-8").decode(bytes);filesScanned++;
   if(manifests.includes(base))parseManifest(path,source,dependencies,diagnostics);
   if(sourceExt.includes(ext))scanSource(path,source,findings);
  }
  const result:ScanResult={findings,dependencies,diagnostics,filesScanned,bytesScanned,durationMs:Math.round(performance.now()-started)};
  worker.postMessage({type:"complete",result});
 }catch(error){worker.postMessage({type:"error",message:error instanceof Error?error.message:"Unknown scan failure"});}
};
export {};
