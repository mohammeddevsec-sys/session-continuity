import crypto from "node:crypto";
const {privateKey,publicKey}=crypto.generateKeyPairSync("ed25519");
const root="AUTH-ROOT-001";
const witness=new Map();
const canon=x=>JSON.stringify(x);
const hash=x=>crypto.createHash("sha256").update(canon(x)).digest("hex");
const makeProof=(sequence,parent,state)=>{const body={root,sequence,parent,state};const sig=crypto.sign(null,Buffer.from(canon(body)),privateKey).toString("base64");return {body,sig};};
const verifySig=p=>crypto.verify(null,Buffer.from(canon(p.body)),publicKey,Buffer.from(p.sig,"base64"));
const submit=p=>{
  if(!verifySig(p))return {ok:false,reason:"INVALID_SIGNATURE"};
  const key=p.body.root; const current=witness.get(key);
  if(!current){if(p.body.sequence!==1)return {ok:false,reason:"FIRST_SEQUENCE_MUST_BE_1"}; witness.set(key,{head:1,proofHash:hash(p.body)}); return {ok:true,reason:"WITNESS_REGISTERED"};}
  if(p.body.sequence<current.head)return {ok:false,reason:"ROLLBACK"};
  if(p.body.sequence===current.head){const h=hash(p.body); if(h===current.proofHash)return {ok:true,reason:"IDEMPOTENT_REPLAY"}; return {ok:false,reason:"EQUIVOCATION_FORK"};}
  if(p.body.sequence!==current.head+1)return {ok:false,reason:"SEQUENCE_GAP"};
  witness.set(key,{head:p.body.sequence,proofHash:hash(p.body)}); return {ok:true,reason:"WITNESS_ADVANCED"};
};
const p1=makeProof(1,"", "STATE-A");
const p2a=makeProof(2,hash(p1.body),"STATE-A2");
const p2b=makeProof(2,hash(p1.body),"STATE-B2");
const p3gap=makeProof(4,hash(p2a.body),"STATE-A4");
const p2same=makeProof(2,hash(p1.body),"STATE-A2");
console.log("=== NON-EQUIVOCATION WITNESS LAB ===");
console.log("P1="+submit(p1).reason);
console.log("P2_A="+submit(p2a).reason);
console.log("P2_B_FORK="+submit(p2b).reason);
console.log("P4_GAP="+submit(p3gap).reason);
console.log("P2_REPLAY_IDENTICAL="+submit(p2same).reason);
console.log("FORK_BLOCKED="+(submit(p2b).reason==="EQUIVOCATION_FORK"?"PASS":"FAIL"));
console.log("GAP_BLOCKED="+(submit(p3gap).reason==="SEQUENCE_GAP"?"PASS":"FAIL"));
console.log("IDENTICAL_REPLAY_IDEMPOTENT="+(submit(p2same).reason==="IDEMPOTENT_REPLAY"?"PASS":"FAIL"));
console.log("WITNESS_HEAD="+witness.get(root).head);
