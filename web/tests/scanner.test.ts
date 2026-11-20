import {describe,it,expect} from "vitest";
import fs from "node:fs";
import path from "node:path";
describe("browser scanner worker",()=>{
 const source=()=>fs.readFileSync(path.resolve("src/scanner.worker.ts"),"utf8");
 it("runs in a dedicated worker and enforces archive budgets",()=>{const s=source();expect(s).toContain("DedicatedWorkerGlobalScope");expect(s).toContain("MAX_ARCHIVE=100*1024*1024");expect(s).toContain("MAX_ENTRIES=5000");expect(s).toContain("MAX_CANDIDATES=2000");expect(s).toContain("MAX_FILE=2*1024*1024");expect(s).toContain("MAX_TOTAL=50*1024*1024");expect(s).toContain('".rs"');expect(s).toContain('".swift"');});
 it("checks declared expansion size before extracting candidate entries",()=>{const s=source();expect(s.indexOf("entry._data?.uncompressedSize")).toBeLessThan(s.indexOf('entry.async("uint8array")'));expect(s).toContain("MAX_RATIO=200");expect(s).toContain("COMPRESSION_RATIO");});
 it("rejects traversal, drive paths, duplicate names and symlinks",()=>{const s=source();expect(s).toContain('parts.includes("..")');expect(s).toContain('/^[a-zA-Z]:/');expect(s).toContain("DUPLICATE_PATH");expect(s).toContain("SYMLINK");});
 it("reports progress and structured scan results",()=>{const s=source();expect(s).toContain('type:"progress"');expect(s).toContain('type:"complete"');expect(s).toContain('type:"error"');});

 it("preflights the File size before allocating its ArrayBuffer",()=>{const s=fs.readFileSync(path.resolve("src/main.ts"),"utf8");expect(s.indexOf("file.size>100*1024*1024")).toBeLessThan(s.indexOf("file.arrayBuffer()"));});
 it("locks file selection during a scan and restores it after cancellation",()=>{const s=fs.readFileSync(path.resolve("src/main.ts"),"utf8");expect(s).toContain("input.disabled=true");expect(s).toContain('input.disabled=false;');expect(s).toContain('Scan cancelled.');});
 it("validates ZIP directory paths before skipping directory entries",()=>{const s=source();expect(s.indexOf("const raw=entry.unsafeOriginalName")).toBeLessThan(s.indexOf("if(isDirectory)continue;"));expect(s).toContain('parts.includes("..")');});
 it("rejects entries whose declared uncompressed size metadata is absent or invalid",()=>{const s=source();expect(s).toContain('code:"SIZE_METADATA"');expect(s.indexOf('code:"SIZE_METADATA"')).toBeLessThan(s.indexOf('entry.async("uint8array")'));});
});
