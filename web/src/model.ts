export type Primitive="signature"|"pke"|"key-agree"|"hash"|"unknown";
export type Finding={id:string;algorithm:string;family:string;primitive:Primitive;purpose:string;file:string;line:number;evidence:string;confidence:"high"|"medium"|"low";quantumVulnerable:boolean|null;recommendation:string};
export type Dependency={name:string;version:string;versionConstraint?:string;ecosystem:string;scope:string;source:string;evidence:"declared"|"locked"|"checksum"|"unknown"};
export type Diagnostic={code:string;message:string;file?:string};
export type ScanResult={findings:Finding[];dependencies:Dependency[];diagnostics:Diagnostic[];filesScanned:number;bytesScanned:number;durationMs:number};
export type BomProperty={name:string;value:string};
export type BomComponent={type:string;name:string;"bom-ref":string;version?:string;cryptoProperties?:{assetType:"algorithm";algorithmProperties:{primitive:Primitive}};properties?:BomProperty[]};
export type Bom={bomFormat:"CycloneDX";specVersion:"1.6";serialNumber:string;version:1;metadata:{timestamp:string;tools:{components:{type:"application";name:string;version:string}[]};component:{type:"application";name:string;"bom-ref":string}};components:BomComponent[];dependencies:{ref:string;dependsOn:string[]}[]};
export async function stableId(value:string):Promise<string>{
 const digest=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(value));
 return Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,"0")).join("");
}
function property(name:string,value:unknown):BomProperty{return{name,value:String(value)};}
export async function buildCbom(scan:ScanResult,project:string):Promise<Bom>{
 const components:BomComponent[]=[],seen=new Set<string>(),applicationRef="urn:sustum:application:"+await stableId(project||"project");
 const dependsOn:string[]=[];
 const findings=[...scan.findings].sort((a,b)=>a.id.localeCompare(b.id));
 for(const f of findings){
  const ref="urn:sustum:crypto:"+await stableId(f.id);if(seen.has(ref))continue;seen.add(ref);dependsOn.push(ref);
  components.push({type:"cryptographic-asset",name:f.algorithm,"bom-ref":ref,cryptoProperties:{assetType:"algorithm",algorithmProperties:{primitive:f.primitive}},properties:[
   property("sustum:asset-kind","source-indicator"),property("sustum:algorithm-family",f.family),property("sustum:purpose",f.purpose),
   property("sustum:source-file",f.file),property("sustum:source-line",f.line),property("sustum:confidence",f.confidence),
   property("sustum:evidence",f.evidence.slice(0,500)),property("sustum:quantum-vulnerable-indicator",f.quantumVulnerable===null?"unknown":f.quantumVulnerable),
   property("sustum:recommendation",f.recommendation.slice(0,500))
  ]});
 }
 const deps=[...scan.dependencies].sort((a,b)=>[a.ecosystem,a.name,a.version,a.versionConstraint??"",a.source,a.scope].join("|").localeCompare([b.ecosystem,b.name,b.version,b.versionConstraint??"",b.source,b.scope].join("|")));
 for(const d of deps){
  const ref="urn:sustum:dependency:"+await stableId([d.ecosystem,d.name,d.version,d.versionConstraint??"",d.source,d.scope].join("|"));if(seen.has(ref))continue;seen.add(ref);dependsOn.push(ref);
  const c:BomComponent={type:"library",name:d.name,"bom-ref":ref,properties:[
   property("sustum:asset-kind","declared-dependency"),property("sustum:ecosystem",d.ecosystem),property("sustum:version-evidence",d.version),...(d.versionConstraint?[property("sustum:version-constraint",d.versionConstraint)]:[]),
   property("sustum:dependency-scope",d.scope),property("sustum:manifest",d.source),property("sustum:evidence-kind",d.evidence),
   property("sustum:crypto-use-confirmed","false")
  ]};
  if(d.version&&d.version!=="unspecified")c.version=d.version;
  components.push(c);
 }
 components.sort((a,b)=>a["bom-ref"].localeCompare(b["bom-ref"]));
 return {bomFormat:"CycloneDX",specVersion:"1.6",serialNumber:"urn:uuid:"+crypto.randomUUID(),version:1,metadata:{
  timestamp:new Date().toISOString(),tools:{components:[{type:"application",name:"SUSTUM PQC Checker",version:"0.1.0"}]},
  component:{type:"application",name:project.trim()||"Scanned project","bom-ref":applicationRef}
 },components,dependencies:dependsOn.length?[{ref:applicationRef,dependsOn:[...new Set(dependsOn)].sort()}]:[]};
}
export function validateCbom(bom:Bom):string[]{
 const errors:string[]=[],applicationRef=bom.metadata.component["bom-ref"],all=new Set<string>([applicationRef]),seen=new Set<string>();
 if(!applicationRef||!applicationRef.startsWith("urn:sustum:application:"))errors.push("Invalid or missing application bom-ref.");
 if(bom.bomFormat!=="CycloneDX"||bom.specVersion!=="1.6"||bom.version!==1)errors.push("Unsupported or malformed CycloneDX document header.");
 if(!/^urn:uuid:[0-9a-f-]{36}$/i.test(bom.serialNumber))errors.push("Invalid CBOM serial number.");
 if(!bom.metadata.timestamp||Number.isNaN(Date.parse(bom.metadata.timestamp)))errors.push("Invalid metadata timestamp.");
 if(!bom.metadata.component.name||!bom.metadata.component["bom-ref"])errors.push("Missing metadata component identity.");
 for(const c of bom.components){
  const ref=c["bom-ref"];
  if(!ref||seen.has(ref)){errors.push("Missing or duplicate bom-ref.");continue;}
  if(ref===applicationRef)errors.push("Component bom-ref collides with metadata application reference.");
  seen.add(ref);all.add(ref);
  if(!c.name||!c.type)errors.push("Component is missing type or name.");
  if(c.type==="cryptographic-asset"){
   if(!c.cryptoProperties||c.cryptoProperties.assetType!=="algorithm"||!c.cryptoProperties.algorithmProperties)errors.push("Cryptographic asset is missing valid cryptoProperties.");
   else if(!["signature","pke","key-agree","hash","unknown"].includes(c.cryptoProperties.algorithmProperties.primitive))errors.push("Unsupported cryptographic primitive.");
  }
 }
 const edgeSources=new Set<string>();
 for(const edge of bom.dependencies){
  if(!all.has(edge.ref))errors.push("Unknown dependency source reference.");
  if(edgeSources.has(edge.ref))errors.push("Duplicate dependency source reference.");
  edgeSources.add(edge.ref);
  const targets=new Set<string>();for(const target of edge.dependsOn){if(!all.has(target))errors.push("Unknown dependency target reference.");if(targets.has(target))errors.push("Duplicate dependency target reference.");targets.add(target);}
 }
 return [...new Set(errors)];
}
