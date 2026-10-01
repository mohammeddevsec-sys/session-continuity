import fs from "fs";
import crypto from "crypto";

export function sha256Text(t){
  return crypto.createHash("sha256").update(t,"utf-8").digest("hex");
}

export function sha256File(p){
  const buf = fs.readFileSync(p);
  return crypto.createHash("sha256").update(buf).digest("hex");
}
