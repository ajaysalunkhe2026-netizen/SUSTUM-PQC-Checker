import {describe,it,expect} from "vitest";
import {buildCbom,validateCbom,type ScanResult} from "../src/model";
const fixture:ScanResult={findings:[{id:"src/a.py:7:RSA",algorithm:"RSA",family:"RSA",primitive:"pke",purpose:"Asymmetric key generation",file:"src/a.py",line:7,evidence:"RSA_generate_key_ex",confidence:"high",quantumVulnerable:true,recommendation:"Review"}],dependencies:[{name:"demo-lib",version:"1.2.0",ecosystem:"npm",scope:"runtime",source:"package.json",evidence:"declared"}],diagnostics:[],filesScanned:2,bytesScanned:120,durationMs:4};
describe("CBOM model",()=>{
 it("creates a CycloneDX 1.6 cryptographic asset",()=>{const b=buildCbom(fixture,"demo");expect(b.specVersion).toBe("1.6");expect(b.components[0].type).toBe("cryptographic-asset");expect(b.components[0].cryptoProperties).toEqual({assetType:"algorithm",algorithmProperties:{primitive:"pke"}});});
 it("keeps manifest dependencies explicitly declared",()=>{const b=buildCbom(fixture,"demo");expect(b.components.some(c=>c.type==="library"&&c.properties?.some(p=>p.name==="sustum:evidence-kind"&&p.value==="declared"))).toBe(true);});
 it("passes internal reference checks",()=>expect(validateCbom(buildCbom(fixture,"demo"))).toEqual([]));
 it("rejects duplicate refs",()=>{const b=buildCbom(fixture,"demo");b.components.push({...b.components[0]});expect(validateCbom(b)).toContain("Missing or duplicate bom-ref.");});
});
