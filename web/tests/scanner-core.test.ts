import {describe,it,expect} from "vitest";
import {maskComments,parseManifest,scanSource} from "../src/scanner-core";
import type {Dependency,Diagnostic,Finding} from "../src/model";
describe("scanner core",()=>{
 it("preserves line positions when masking comments",()=>{const s="/* comment\ncontinued */\ncrypto.generateKeyPairSync('rsa', {});";const m=maskComments(s,".js");expect(m.split("\n")).toHaveLength(3);});
 it("preserves comment-like text inside quoted strings",()=>{const s='const url = "https://example.test/a"; // crypto.generateKeyPairSync(\'rsa\', {});\ncrypto.generateKeyPairSync("rsa", {});';const m=maskComments(s,".js");expect(m).toContain("https://example.test/a");expect(m).not.toContain("// crypto.generateKeyPairSync");expect(m).toContain('crypto.generateKeyPairSync("rsa", {})');});
 it("masks Python comments but preserves hash characters in strings",()=>{const s='url = "https://example.test/#frag" # comment\nuse_crypto()';const m=maskComments(s,".py");expect(m).toContain("https://example.test/#frag");expect(m).not.toContain("# comment");});
 it("masks Python triple-quoted content without changing line count",()=>{const s='value = """first # text\ncrypto.generateKeyPairSync("rsa", {})\nlast"""\nreal_call()';const m=maskComments(s,".py");expect(m.split("\n")).toHaveLength(4);expect(m).toContain("crypto.generateKeyPairSync");});
 it("detects a supported RSA API with evidence and source location",()=>{const out:Finding[]=[];scanSource("src/a.js","crypto.generateKeyPairSync('rsa', {});",out);expect(out).toHaveLength(1);expect(out[0].algorithm).toBe("RSA");expect(out[0].line).toBe(1);expect(out[0].confidence).toBe("high");});
 it("does not classify a comment-only API mention",()=>{const out:Finding[]=[];scanSource("src/a.js","// crypto.generateKeyPairSync('rsa', {});",out);expect(out).toHaveLength(0);});
 it("does not report API-shaped text inside JavaScript strings",()=>{const out:Finding[]=[];scanSource("src/a.js",'const sample = "crypto.generateKeyPairSync(\\'rsa\\', {})";',out);expect(out).toHaveLength(0);});
 it("does not report API-shaped text inside Python triple-quoted strings",()=>{const out:Finding[]=[];scanSource("src/a.py",'sample = """crypto.generateKeyPairSync("rsa", {})"""',out);expect(out).toHaveLength(0);});
 it("keeps dependency manifest evidence separate from observed crypto use",()=>{const deps:Dependency[]=[],diag:Diagnostic[]=[];parseManifest("package.json",JSON.stringify({dependencies:{"example-lib":"^2.0.0"}}),deps,diag);expect(deps[0]).toMatchObject({name:"example-lib",version:"^2.0.0",evidence:"declared"});expect(diag).toHaveLength(0);});
 it("emits a diagnostic for invalid package.json",()=>{const deps:Dependency[]=[],diag:Diagnostic[]=[];parseManifest("package.json","[]",deps,diag);expect(diag[0].code).toBe("MANIFEST_JSON");});
});
