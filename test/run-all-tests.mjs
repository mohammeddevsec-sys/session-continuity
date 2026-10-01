import fs from "fs";
import path from "path";
import { spawnSync } from "child_process";

const testDir=path.join(process.cwd(),"test");
const tests=fs.readdirSync(testDir).filter(name=>name.endsWith(".js") && name!=="run-all-tests.mjs").sort();
let failed=0;
console.log("");
console.log("=== SESSION CONTINUITY :: FINAL REGRESSION ===");
for(const name of tests){
  const file=path.join(testDir,name);
  console.log("");
  console.log("=== TEST: "+name+" ===");
  const result=spawnSync(process.execPath,[file],{stdio:"inherit"});
  if(result.error){
    console.log("RESULT=FAIL|"+result.error.message);
    failed++;
  }else if(result.status!==0){
    console.log("RESULT=FAIL|EXIT="+result.status);
    failed++;
  }else{
    console.log("RESULT=PASS");
  }
}
console.log("");
if(failed>0){
  console.log("FINAL_REGRESSION=FAIL|FAILED="+failed);
  process.exit(1);
}
console.log("FINAL_REGRESSION=PASS|TESTS="+tests.length);
console.log("PRODUCT_STATE=STABLE_BASELINE");