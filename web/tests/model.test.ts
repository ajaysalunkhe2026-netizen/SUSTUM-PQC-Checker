import {describe,it,expect} from "vitest";
import {buildCbom,validateCbom,type ScanResult} from "../src/model";
const fixture:ScanResult={findings:[{id:"src/a.py:7:RSA",algorithm:"RSA",family:"RSA",primitive:"unknown",purpose:"Asymmetric key generation",file:"src/a.py",line:7,evidence:"RSA_generate_key_ex",confidence:"high",quantumVulnerable:true,recommendation:"Review"}],dependencies:[{name:"demo-lib",version:"unspecified",versionConstraint:"^1.2.0",ecosystem:"npm",scope:"runtime",source:"package.json",evidence:"declared"}],diagnostics:[],filesScanned:2,bytesScanned:120,durationMs:4};
describe("CBOM model",()=>{
 it("creates a CycloneDX 1.6 cryptographic asset",async()=>{const b=await buildCbom(fixture,"demo");expect(b.specVersion).toBe("1.6");expect(b.components.find(c=>c.type==="cryptographic-asset")?.cryptoProperties).toEqual({assetType:"algorithm",algorithmProperties:{primitive:"unknown"}});});
 it("keeps manifest dependencies explicitly declared and not confirmed crypto use",async()=>{const b=await buildCbom(fixture,"demo");expect(b.components.some(c=>c.type==="library"&&c.properties?.some(p=>p.name==="sustum:evidence-kind"&&p.value==="declared"))).toBe(true);expect(b.components.find(c=>c.type==="library")?.properties?.some(p=>p.name==="sustum:crypto-use-confirmed"&&p.value==="false")).toBe(true);});
 it("preserves version constraints as provenance rather than component versions",async()=>{const b=await buildCbom(fixture,"demo");const lib=b.components.find(c=>c.type==="library");expect(lib?.version).toBeUndefined();expect(lib?.properties?.some(p=>p.name==="sustum:version-constraint"&&p.value==="^1.2.0")).toBe(true);});
 it("creates application-to-asset relationship edges",async()=>{const b=await buildCbom(fixture,"demo");expect(b.dependencies).toHaveLength(1);expect(b.dependencies[0].dependsOn).toHaveLength(2);});
 it("passes internal reference checks",async()=>expect(validateCbom(await buildCbom(fixture,"demo"))).toEqual([]));
 it("rejects duplicate refs",async()=>{const b=await buildCbom(fixture,"demo");b.components.push({...b.components[0]});expect(validateCbom(b)).toContain("Missing or duplicate bom-ref.");});
 it("rejects dangling relationship references",async()=>{const b=await buildCbom(fixture,"demo");b.dependencies[0].dependsOn.push("missing-ref");expect(validateCbom(b)).toContain("Unknown dependency target reference.");});
});
