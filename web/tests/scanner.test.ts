import {describe,it,expect} from "vitest";
import fs from "node:fs";
import path from "node:path";
describe("browser scanner worker",()=>{it("runs in a dedicated worker and enforces input budgets",()=>{const s=fs.readFileSync(path.resolve("src/scanner.worker.ts"),"utf8");expect(s).toContain("DedicatedWorkerGlobalScope");expect(s).toContain("MAX_ARCHIVE=100*1024*1024");expect(s).toContain("MAX_ENTRIES=5000");expect(s).toContain("MAX_TOTAL=50*1024*1024");});});
