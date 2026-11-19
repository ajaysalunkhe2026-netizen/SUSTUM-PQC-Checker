import type {ScanResult} from "./model";
import {buildCbom,validateCbom} from "./model";
import "./style.css";
const root=document.querySelector<HTMLDivElement>("#app");
if(!root)throw new Error("Application root missing.");
root.innerHTML = [
'<header><div class="brand"><span class="mark">PQ</span><div><h1>SUSTUM PQC Checker</h1><p>Browser-local cryptographic inventory</p></div></div><span class="privacy">Files stay on this device</span></header>',
'<main><section class="panel intro"><h2>Post-Quantum Readiness Scan</h2><p>Choose a ZIP project archive. Extraction and scanning run locally in a Web Worker. The archive is not uploaded.</p><label class="drop" for="archive"><strong>Select project ZIP</strong><span>Maximum archive 100 MiB · 5,000 entries · candidate files 2 MiB each</span><input id="archive" type="file" accept=".zip,application/zip"></label><button id="scan" disabled>Run local scan</button><p id="status" role="status" aria-live="polite">Waiting for an archive.</p></section>',
'<section id="results" hidden><div class="metrics"><article><b id="files">0</b><span>Files scanned</span></article><article><b id="findings">0</b><span>Crypto indicators</span></article><article><b id="deps">0</b><span>Dependencies</span></article><article><b id="diagnostics">0</b><span>Diagnostics</span></article></div>',
'<section class="panel"><h2>Assessment & exports</h2><p id="summary"></p><div class="actions"><button id="cbom">Download CycloneDX 1.6 CBOM</button><button id="csv" class="secondary">Findings CSV</button><button id="json" class="secondary">Scan JSON</button></div><p id="cbom-status" class="muted" aria-live="polite"></p></section>',
'<section class="panel"><h2>Cryptographic findings</h2><div class="tablewrap"><table><thead><tr><th>Algorithm</th><th>Purpose</th><th>Source</th><th>Confidence</th><th>Evidence</th><th>Review</th></tr></thead><tbody id="finding-rows"></tbody></table></div></section>',
'<section class="panel"><h2>Dependency inventory</h2><p class="muted">A manifest entry is not proof of cryptographic use.</p><div class="tablewrap"><table><thead><tr><th>Package</th><th>Version/constraint</th><th>Ecosystem</th><th>Scope</th><th>Source</th></tr></thead><tbody id="dep-rows"></tbody></table></div></section>',
'<section class="panel"><h2>Diagnostics & limitations</h2><ul id="diag-rows"></ul><p class="muted">Heuristic static analysis cannot prove reachability or runtime use, and cannot discover binary-only crypto, remote services, HSMs, runtime-loaded keys or all language constructs. A clean scan does not prove that cryptography is absent.</p></section></section></main>',
'<footer>SUSTUM · Local-first browser scanner · Review every finding before migration or compliance decisions.</footer>'
].join("");
const $=<T extends HTMLElement>(id:string)=>{const e=document.getElementById(id);if(!e)throw new Error("Missing UI element: "+id);return e as T;};
const input=$<HTMLInputElement>("archive"),scanButton=$<HTMLButtonElement>("scan"),status=$<HTMLParagraphElement>("status");
let latest:ScanResult|null=null;
input.addEventListener("change",()=>{scanButton.disabled=!input.files?.length;status.textContent=input.files?.[0]?.name??"Waiting for an archive.";});
scanButton.addEventListener("click",async()=>{
 const file=input.files?.[0];if(!file)return;
 scanButton.disabled=true;status.textContent="Reading archive locally…";
 const worker=new Worker(new URL("./scanner.worker.ts",import.meta.url),{type:"module"});
 worker.onmessage=(event:MessageEvent)=>{
  worker.terminate();scanButton.disabled=false;
  if(event.data.type==="error"){status.textContent="Scan failed: "+event.data.message;return;}
  latest=event.data.result as ScanResult;render(latest);
  status.textContent="Scan completed in "+latest.durationMs+" ms. No source upload was performed.";
 };
 worker.onerror=()=>{worker.terminate();scanButton.disabled=false;status.textContent="Worker failed. No archive was uploaded.";};
 try{const buffer=await file.arrayBuffer();worker.postMessage({type:"scan",buffer},[buffer]);}
 catch(error){worker.terminate();scanButton.disabled=false;status.textContent="Unable to read archive: "+String(error);}
});
function render(r:ScanResult){
 $("results").removeAttribute("hidden");$("files").textContent=String(r.filesScanned);$("findings").textContent=String(r.findings.length);$("deps").textContent=String(r.dependencies.length);$("diagnostics").textContent=String(r.diagnostics.length);
 $("summary").textContent=r.findings.length+" indicators need human review. "+r.findings.filter(x=>x.quantumVulnerable===true).length+" have a quantum-vulnerable indicator; this is not an exploitability or compliance verdict.";
 const findings=$("finding-rows");findings.replaceChildren();
 for(const f of r.findings){const tr=document.createElement("tr");for(const value of [f.algorithm,f.purpose,f.file+":"+f.line,f.confidence,f.evidence,f.quantumVulnerable===true?"Prioritize review":f.quantumVulnerable===false?"Context review":"Unknown / manual review"]){const td=document.createElement("td");td.textContent=value;tr.append(td);}findings.append(tr);}
 const deps=$("dep-rows");deps.replaceChildren();
 for(const d of r.dependencies){const tr=document.createElement("tr");for(const value of [d.name,d.version,d.ecosystem,d.scope,d.source]){const td=document.createElement("td");td.textContent=value;tr.append(td);}deps.append(tr);}
 const diagnostics=$("diag-rows");diagnostics.replaceChildren();
 for(const d of r.diagnostics){const li=document.createElement("li");li.textContent=d.code+": "+d.message+" "+(d.file??"");diagnostics.append(li);}
}
function download(name:string,data:string,type:string){const url=URL.createObjectURL(new Blob([data],{type}));const a=document.createElement("a");a.href=url;a.download=name;document.body.append(a);a.click();a.remove();URL.revokeObjectURL(url);}
$("cbom").addEventListener("click",async()=>{if(!latest)return;const bom=await buildCbom(latest,input.files?.[0]?.name??"project");const errors=validateCbom(bom);$("cbom-status").textContent=errors.length?"Internal checks failed: "+errors.join(" "):"Internal reference checks passed. Official CycloneDX schema and independent-consumer validation are still required.";download("sustum-cbom-1.6.json",JSON.stringify(bom,null,2),"application/json");});
$("csv").addEventListener("click",()=>{if(!latest)return;const rows=[["algorithm","purpose","file","line","confidence","evidence","quantum_vulnerable"],...latest.findings.map(f=>[f.algorithm,f.purpose,f.file,String(f.line),f.confidence,f.evidence,String(f.quantumVulnerable)])];const csv=rows.map(row=>row.map(v=>'"'+v.replace(/"/g,'""')+'"').join(",")).join("\n");download("sustum-findings.csv",csv,"text/csv");});
$("json").addEventListener("click",()=>{if(latest)download("sustum-scan.json",JSON.stringify(latest,null,2),"application/json");});
