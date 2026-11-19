export type Primitive = "signature"|"pke"|"key-agree"|"hash"|"unknown";
export type Finding = { id:string; algorithm:string; family:string; primitive:Primitive; purpose:string; file:string; line:number; evidence:string; confidence:"high"|"medium"|"low"; quantumVulnerable:boolean|null; recommendation:string };
export type Dependency = { name:string; version:string; ecosystem:string; scope:string; source:string; evidence:"declared"|"locked"|"checksum"|"unknown" };
export type Diagnostic = { code:string; message:string; file?:string };
export type ScanResult = { findings:Finding[]; dependencies:Dependency[]; diagnostics:Diagnostic[]; filesScanned:number; bytesScanned:number; durationMs:number };
export type BomComponent = { type:string; name:string; "bom-ref":string; version?:string; cryptoProperties?:{assetType:"algorithm";algorithmProperties:{primitive:Primitive}}; properties?:{name:string;value:string}[] };
export type Bom = { bomFormat:"CycloneDX"; specVersion:"1.6"; serialNumber:string; version:1; metadata:{timestamp:string;tools:{components:{type:"application";name:string;version:string}[]};component:{type:"application";name:string;"bom-ref":string}}; components:BomComponent[]; dependencies:{ref:string;dependsOn:string[]}[] };
export function stableId(s:string):string {
 let h=2166136261; for(let i=0;i<s.length;i++){h^=s.charCodeAt(i);h=Math.imul(h,16777619);} return (h>>>0).toString(16).padStart(8,"0")+"-"+s.length.toString(16);
}
export function buildCbom(scan:ScanResult,project:string):Bom {
 const components:BomComponent[]=[], seen=new Set<string>(), edges:{ref:string;dependsOn:string[]}[]=[];
 const appRef="sustum:application:"+stableId(project);
 for(const f of [...scan.findings].sort((a,b)=>a.id.localeCompare(b.id))){
  const ref="sustum:crypto:"+stableId(f.id); if(seen.has(ref))continue; seen.add(ref);
  components.push({type:"cryptographic-asset",name:f.algorithm,"bom-ref":ref,cryptoProperties:{assetType:"algorithm",algorithmProperties:{primitive:f.primitive}},properties:[
   {name:"sustum:algorithm-family",value:f.family},{name:"sustum:purpose",value:f.purpose},{name:"sustum:source-file",value:f.file},{name:"sustum:source-line",value:String(f.line)},
   {name:"sustum:confidence",value:f.confidence},{name:"sustum:evidence",value:f.evidence.slice(0,500)},
   {name:"sustum:quantum-vulnerable-indicator",value:f.quantumVulnerable===null?"unknown":String(f.quantumVulnerable)}
  ]});
 }
 const packageRefs:string[]=[];
 for(const d of [...scan.dependencies].sort((a,b)=>(a.ecosystem+a.name+a.version+a.source).localeCompare(b.ecosystem+b.name+b.version+b.source))){
  const ref="sustum:dependency:"+stableId([d.ecosystem,d.name,d.version,d.source].join("|"));if(seen.has(ref))continue;seen.add(ref);packageRefs.push(ref);
  const c:BomComponent={type:"library",name:d.name,"bom-ref":ref,properties:[{name:"sustum:ecosystem",value:d.ecosystem},{name:"sustum:version-evidence",value:d.version},{name:"sustum:dependency-scope",value:d.scope},{name:"sustum:manifest",value:d.source},{name:"sustum:evidence-kind",value:d.evidence}]};
  if(d.version&&d.version!=="unspecified")c.version=d.version;components.push(c);
 }
 if(packageRefs.length)edges.push({ref:appRef,dependsOn:packageRefs});
 return {bomFormat:"CycloneDX",specVersion:"1.6",serialNumber:"urn:uuid:"+crypto.randomUUID(),version:1,metadata:{timestamp:new Date().toISOString(),tools:{components:[{type:"application",name:"SUSTUM PQC Checker",version:"0.1.0"}]},component:{type:"application",name:project||"Scanned project","bom-ref":appRef}},components,dependencies:edges};
}
export function validateCbom(b:Bom):string[]{
 const errors:string[]=[],refs=new Set<string>(),all=new Set<string>([b.metadata.component["bom-ref"]]);
 for(const c of b.components){if(!c["bom-ref"]||refs.has(c["bom-ref"]))errors.push("Missing or duplicate bom-ref.");else{refs.add(c["bom-ref"]);all.add(c["bom-ref"]);}if(c.type==="cryptographic-asset"&&(!c.cryptoProperties||c.cryptoProperties.assetType!=="algorithm"))errors.push("Cryptographic asset is missing valid cryptoProperties.");}
 for(const e of b.dependencies){if(!all.has(e.ref))errors.push("Unknown dependency source reference.");for(const d of e.dependsOn)if(!all.has(d))errors.push("Unknown dependency target reference.");}
 return errors;
}
