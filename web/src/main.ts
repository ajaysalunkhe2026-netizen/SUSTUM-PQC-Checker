import type {ScanResult} from "./model";
import {buildCbom,validateCbom} from "./model";
import "./style.css";

const root=document.querySelector<HTMLDivElement>("#app");
if(!root)throw new Error("Application root missing.");
root.innerHTML=[
'<header><div class="brand"><span class="mark">PQ</span><div><h1>SUSTUM PQC Checker</h1><p>Browser-local cryptographic inventory</p></div></div><span class="privacy">Files stay on this device</span></header>',
'<main><section class="panel intro"><h2>Post-Quantum Readiness Scan</h2><p>Choose a ZIP project archive. Extraction and scanning run locally in a Web Worker. The archive is not uploaded.</p><label class="drop" for="archive"><strong>Select project ZIP</strong><span>Maximum archive 100 MiB · 5,000 entries · 2,000 candidate files · 2 MiB per file. ZIP is processed locally.</span><input id="archive" type="file" accept=".zip,application/zip" aria-describedby="status"></label><div class="actions"><button id="scan" disabled>Run local scan</button><button id="cancel" class="secondary" disabled>Cancel scan</button></div><p id="status" role="status" aria-live="polite">Waiting for an archive.</p></section>',
'<section id="results" hidden><div class="metrics"><article><b id="files">0</b><span>Files scanned</span></article><article><b id="findings">0</b><span>Crypto indicators</span></article><article><b id="deps">0</b><span>Dependencies</span></article><article><b id="diagnostics">0</b><span>Diagnostics</span></article></div>',
'<section class="panel"><h2>Assessment & exports</h2><p id="summary"></p><div class="actions"><button id="cbom">Download CycloneDX 1.6 CBOM</button><button id="csv" class="secondary">Findings CSV</button><button id="json" class="secondary">Scan JSON</button></div><p id="cbom-status" class="muted" aria-live="polite"></p></section>',
'<section class="panel"><h2>Cryptographic findings</h2><div class="filters"><label>Search findings<input id="finding-search" type="search" placeholder="Algorithm, file, evidence…"></label><label>Confidence<select id="confidence-filter"><option value="all">All confidence levels</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label><label>Algorithm<select id="algorithm-filter"><option value="all">All algorithms</option></select></label><span id="finding-count" role="status" aria-live="polite"></span></div><div class="tablewrap"><table><thead><tr><th scope="col">Algorithm</th><th scope="col">Purpose</th><th scope="col">Source</th><th scope="col">Confidence</th><th scope="col">Evidence</th><th scope="col">Review</th><th scope="col">Suggested next step</th></tr></thead><tbody id="finding-rows"></tbody></table></div></section>',
'<section class="panel"><h2>Dependency inventory</h2><p class="muted">A manifest entry is not proof of cryptographic use.</p><div class="tablewrap"><table><thead><tr><th scope="col">Package</th><th scope="col">Version/constraint</th><th scope="col">Ecosystem</th><th scope="col">Scope</th><th scope="col">Source</th></tr></thead><tbody id="dep-rows"></tbody></table></div></section>',
'<section class="panel"><h2>Diagnostics & limitations</h2><ul id="diag-rows"></ul><p class="muted">Heuristic static analysis cannot prove reachability or runtime use, and cannot discover binary-only crypto, remote services, HSMs, runtime-loaded keys or all language constructs. A clean scan does not prove that cryptography is absent.</p></section></section></main>',
'<footer>SUSTUM · Local-first browser scanner · Review every finding before migration or compliance decisions.</footer>'
].join("");

const $=<T extends HTMLElement>(id:string):T=>{
 const element=document.getElementById(id);
 if(!element)throw new Error("Missing UI element: "+id);
 return element as T;
};
const input=$<HTMLInputElement>("archive");
const scanButton=$<HTMLButtonElement>("scan");
const cancelButton=$<HTMLButtonElement>("cancel");
const status=$<HTMLParagraphElement>("status");
let activeWorker:Worker|null=null;
let latest:ScanResult|null=null;
let latestProjectName="project";
const findingSearch=$<HTMLInputElement>("finding-search");
const confidenceFilter=$<HTMLSelectElement>("confidence-filter");
const algorithmFilter=$<HTMLSelectElement>("algorithm-filter");
findingSearch.addEventListener("input",()=>{if(latest)renderFindings(latest);});
confidenceFilter.addEventListener("change",()=>{if(latest)renderFindings(latest);});
algorithmFilter.addEventListener("change",()=>{if(latest)renderFindings(latest);});

input.addEventListener("change",()=>{
 if(activeWorker){activeWorker.terminate();activeWorker=null;}
 input.disabled=false;
 cancelButton.disabled=true;
 latest=null;
 $("results").hidden=true;
 scanButton.disabled=!input.files?.length||!!activeWorker;
 status.textContent=input.files?.[0]?.name??"Waiting for an archive.";
});
cancelButton.addEventListener("click",()=>{
 if(!activeWorker)return;
 activeWorker.terminate();
 activeWorker=null;
 input.disabled=false;
 scanButton.disabled=!input.files?.length;
 cancelButton.disabled=true;
 status.textContent="Scan cancelled. The archive was not uploaded.";
});
scanButton.addEventListener("click",async()=>{
 const file=input.files?.[0];
 if(!file||activeWorker)return;
 if(file.size>100*1024*1024){status.textContent="Archive exceeds 100 MiB. Choose a smaller ZIP before it is read into memory.";return;}
 if(!file.name.toLowerCase().endsWith(".zip")){
  status.textContent="Please select a .zip archive.";
  return;
 }
 scanButton.disabled=true;
 input.disabled=true;
 cancelButton.disabled=false;
 latest=null;
 latestProjectName=file.name;
 $("results").hidden=true;
 status.textContent="Reading archive locally…";
 let worker:Worker;
 try{worker=new Worker(new URL("./scanner.worker.ts",import.meta.url),{type:"module"});}
 catch(error){input.disabled=false;scanButton.disabled=!input.files?.length;cancelButton.disabled=true;status.textContent="Unable to start the local scanner worker: "+String(error);return;}
 activeWorker=worker;
 worker.onmessage=(event:MessageEvent)=>{
  if(activeWorker!==worker)return;
  if(event.data.type==="progress"){
   status.textContent=String(event.data.message);
   return;
  }
  activeWorker=null;
  worker.terminate();
  cancelButton.disabled=true;
  input.disabled=false;
  scanButton.disabled=!input.files?.length;
  if(event.data.type==="error"){
   status.textContent="Scan failed: "+String(event.data.message);
   return;
  }
  latest=event.data.result as ScanResult;
  render(latest);
  status.textContent="Scan completed in "+latest.durationMs+" ms. No source upload was performed.";
 };
 worker.onerror=()=>{
  if(activeWorker!==worker)return;
  activeWorker=null;
  worker.terminate();
  input.disabled=false;
  cancelButton.disabled=true;
  scanButton.disabled=!input.files?.length;
  status.textContent="Worker failed. No archive was uploaded.";
 };
 try{
  const buffer=await file.arrayBuffer();
  if(activeWorker!==worker)return;
  if(input.files?.[0]!==file){activeWorker=null;worker.terminate();input.disabled=false;cancelButton.disabled=true;scanButton.disabled=!input.files?.length;status.textContent="Selected archive changed; scan discarded.";return;}
  worker.postMessage({type:"scan",buffer},[buffer]);
 }catch(error){
  if(activeWorker!==worker)return;
  activeWorker=null;
  worker.terminate();
  input.disabled=false;
  cancelButton.disabled=true;
  scanButton.disabled=!input.files?.length;
  status.textContent="Unable to read archive: "+String(error);
 }
});

function render(result:ScanResult):void{
 $("results").removeAttribute("hidden");
 $("files").textContent=String(result.filesScanned);
 $("findings").textContent=String(result.findings.length);
 $("deps").textContent=String(result.dependencies.length);
 $("diagnostics").textContent=String(result.diagnostics.length);
 $("summary").textContent=result.findings.length+" indicators need human review. "+result.findings.filter(x=>x.quantumVulnerable===true).length+" have a quantum-vulnerable indicator; this is not an exploitability or compliance verdict.";
 renderFindings(result);
 const deps=$("dep-rows");
 deps.replaceChildren();
 for(const dependency of result.dependencies){
  const tr=document.createElement("tr");
  for(const value of [dependency.name,dependency.versionConstraint?dependency.version+" · "+dependency.versionConstraint:dependency.version,dependency.ecosystem,dependency.scope,dependency.source]){
   const td=document.createElement("td");
   td.textContent=value;
   tr.append(td);
  }
  deps.append(tr);
 }
 const diagnostics=$("diag-rows");
 diagnostics.replaceChildren();
 for(const diagnostic of result.diagnostics){
  const li=document.createElement("li");
  li.textContent=diagnostic.code+": "+diagnostic.message+" "+(diagnostic.file??"");
  diagnostics.append(li);
 }
}
function renderFindings(result:ScanResult):void{
 const rows=$("finding-rows");rows.replaceChildren();
 const algorithms=[...new Set(result.findings.map(f=>f.algorithm))].sort();
 const selected=algorithmFilter.value;
 algorithmFilter.replaceChildren(new Option("All algorithms","all"),...algorithms.map(a=>new Option(a,a)));
 if(selected!=="all"&&algorithms.includes(selected))algorithmFilter.value=selected;
 const query=findingSearch.value.trim().toLowerCase(),confidence=confidenceFilter.value,algorithm=algorithmFilter.value;
 const filtered=result.findings.filter(f=>(confidence==="all"||f.confidence===confidence)&&(algorithm==="all"||f.algorithm===algorithm)&&(!query||[f.algorithm,f.family,f.purpose,f.file,f.evidence,f.recommendation].join(" ").toLowerCase().includes(query)));
 $("finding-count").textContent="Showing "+filtered.length+" of "+result.findings.length+" indicators";
 for(const finding of filtered){
  const tr=document.createElement("tr");
  const review=finding.quantumVulnerable===true?"Prioritize review":finding.quantumVulnerable===false?"Context review":"Unknown / manual review";
  for(const value of [finding.algorithm,finding.purpose,finding.file+":"+finding.line,finding.confidence,finding.evidence,review,finding.recommendation]){
   const td=document.createElement("td");td.textContent=value;tr.append(td);
  }
  rows.append(tr);
 }
}
function download(name:string,data:string,type:string):void{
 const url=URL.createObjectURL(new Blob([data],{type}));
 const anchor=document.createElement("a");
 anchor.href=url;
 anchor.download=name;
 document.body.append(anchor);
 anchor.click();
 anchor.remove();
 window.setTimeout(()=>URL.revokeObjectURL(url),1000);
}
$("cbom").addEventListener("click",async()=>{
 if(!latest)return;
 try{
  const bom=await buildCbom(latest,latestProjectName);
  const errors=validateCbom(bom);
  if(errors.length){$("cbom-status").textContent="CBOM internal validation failed: "+errors.join(" ");return;}
  $("cbom-status").textContent="Internal structure and reference checks passed. Official schema and independent-consumer validation remain separate release gates.";
  download("sustum-cbom-1.6.json",JSON.stringify(bom,null,2),"application/json");
 }catch(error){
  $("cbom-status").textContent="CBOM generation failed: "+String(error);
 }
});
$("csv").addEventListener("click",()=>{
 if(!latest)return;
 const rows=[["algorithm","purpose","file","line","confidence","evidence","quantum_vulnerable","recommendation"],...latest.findings.map(f=>[f.algorithm,f.purpose,f.file,String(f.line),f.confidence,f.evidence,String(f.quantumVulnerable),f.recommendation])];
 const csv=rows.map(row=>row.map(value=>{const first=value.trimStart()[0];const safe=first==="="||first==="+"||first==="-"||first==="@"?"'"+value:value;return '"'+safe.replace(/"/g,'""')+'"';}).join(",")).join("\n");
 download("sustum-findings.csv",csv,"text/csv");
});
$("json").addEventListener("click",()=>{
 if(latest)download("sustum-scan.json",JSON.stringify(latest,null,2),"application/json");
});
