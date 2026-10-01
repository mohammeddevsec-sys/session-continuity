import crypto from "node:crypto";

function assertJsonString(value){
  for(let i=0;i<value.length;i++){
    const c=value.charCodeAt(i);
    if(c>=0xD800&&c<=0xDBFF){
      if(i+1>=value.length) throw new TypeError("JCS_LONE_HIGH_SURROGATE");
      const n=value.charCodeAt(i+1);
      if(n<0xDC00||n>0xDFFF) throw new TypeError("JCS_LONE_HIGH_SURROGATE");
      i++;
    }else if(c>=0xDC00&&c<=0xDFFF){
      throw new TypeError("JCS_LONE_LOW_SURROGATE");
    }
  }
}

function serialize(value){
  if(value===null)return "null";
  const type=typeof value;
  if(type==="string"){assertJsonString(value);return JSON.stringify(value);}
  if(type==="boolean")return value?"true":"false";
  if(type==="number"){
    if(!Number.isFinite(value)||Number.isNaN(value))throw new TypeError("JCS_NUMBER_INVALID");
    if(Object.is(value,-0))throw new TypeError("JCS_NEGATIVE_ZERO_REJECTED");
    return JSON.stringify(value);
  }
  if(type==="bigint"||type==="undefined"||type==="function"||type==="symbol")throw new TypeError(`JCS_UNSUPPORTED_TYPE:${type}`);
  if(Array.isArray(value))return "["+value.map(serialize).join(",")+"]";
  if(Object.getPrototypeOf(value)!==Object.prototype&&Object.getPrototypeOf(value)!==null)throw new TypeError("JCS_OBJECT_TYPE_INVALID");
  const keys=Object.keys(value).sort();
  return "{"+keys.map(k=>{assertJsonString(k);return JSON.stringify(k)+":"+serialize(value[k]);}).join(",")+"}";
}

export function jcsCanonicalize(value){return serialize(value);}

export function jcsSha256(value){return crypto.createHash("sha256").update(Buffer.from(jcsCanonicalize(value),"utf8")).digest("hex");}