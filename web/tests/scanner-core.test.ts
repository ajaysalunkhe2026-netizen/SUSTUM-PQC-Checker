import {describe,it,expect} from "vitest";
import {maskComments,parseManifest,scanSource} from "../src/scanner-core";
import type {Dependency,Diagnostic,Finding} from "../src/model";
describe("scanner core",()=>{
 it("preserves line positions when masking comments",()=>{const s="/* comment\ncontinued */\ncrypto.generateKeyPairSync('rsa', {});";const m=maskComments(s,".js");expect(m.split("\n")).toHaveLength(3);});
 it("detects a supported RSA API with evidence and source location",()=>{const out:Finding[]=[];scanSource("src/a.js","crypto.generateKeyPairSync('rsa', {});",out);expect(out).toHaveLength(1);expect(out[0].algorithm).toBe("RSA");expect(out[0].line).toBe(1);expect(out[0].confidence).toBe("high");});
 it("does not classify a comment-only API mention",()=>{const out:Finding[]=[];scanSource("src/a.js","// crypto.generateKeyPairSync('rsa', {});",out);expect(out).toHaveLength(0);});
 it("keeps dependency manifest evidence separate from observed crypto use",()=>{const deps:Dependency[]=[],diag:Diagnostic[]=[];parseManifest("package.json",JSON.stringify({dependencies:{"example-lib":"^2.0.0"}}),deps,diag);expect(deps[0]).toMatchObject({name:"example-lib",version:"^2.0.0",evidence:"declared"});expect(diag).toHaveLength(0);});
 it("emits a diagnostic for invalid package.json",()=>{const deps:Dependency[]=[],diag:Diagnostic[]=[];parseManifest("package.json","[]",deps,diag);expect(diag[0].code).toBe("MANIFEST_JSON");});
});
