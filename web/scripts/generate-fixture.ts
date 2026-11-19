import {buildCbom,type ScanResult} from "../src/model";
const scan:ScanResult={findings:[{id:"src/demo.py:8:RSA",algorithm:"RSA",family:"RSA",primitive:"pke",purpose:"Key generation",file:"src/demo.py",line:8,evidence:"RSA_generate_key_ex",confidence:"high",quantumVulnerable:true,recommendation:"Review"}],dependencies:[{name:"sample-package",version:"1.2.3",ecosystem:"npm",scope:"runtime",source:"package.json",evidence:"declared"}],diagnostics:[],filesScanned:1,bytesScanned:42,durationMs:1};
process.stdout.write(JSON.stringify(await buildCbom(scan,"schema-validation-fixture")));
