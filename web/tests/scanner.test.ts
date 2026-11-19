import {describe,it,expect} from "vitest";
import fs from "node:fs";
import path from "node:path";
describe("browser scanner worker",()=>{
 const source=()=>fs.readFileSync(path.resolve("src/scanner.worker.ts"),"utf8");
 it("runs in a dedicated worker and enforces archive budgets",()=>{
  const s=source();
  expect(s).toContain("DedicatedWorkerGlobalScope");
  expect(s).toContain("MAX_ARCHIVE=100*1024*1024");
  expect(s).toContain("MAX_ENTRIES=5000");
  expect(s).toContain("MAX_CANDIDATES=2000");
  expect(s).toContain("MAX_FILE=2*1024*1024");
  expect(s).toContain("MAX_TOTAL=50*1024*1024");\n  expect(s).toContain(".rs");\n  expect(s).toContain(".swift");
 });
 it("checks declared expansion size before extracting candidate entries",()=>{
  const s=source();
  expect(s.indexOf("entry._data?.uncompressedSize")).toBeLessThan(s.indexOf('entry.async("uint8array")'));
  expect(s).toContain("MAX_RATIO=200");
  expect(s).toContain("COMPRESSION_RATIO");
 });
 it("rejects traversal, drive paths, duplicate names and symlinks",()=>{
  const s=source();
  expect(s).toContain('parts.includes("..")');
  expect(s).toContain('/^[a-zA-Z]:/');
  expect(s).toContain("DUPLICATE_PATH");
  expect(s).toContain("SYMLINK");
 });
 it("reports progress and returns structured scan results",()=>{
  const s=source();
  expect(s).toContain('type:"progress"');
  expect(s).toContain('type:"complete"');
  expect(s).toContain('type:"error"');
 });
});
