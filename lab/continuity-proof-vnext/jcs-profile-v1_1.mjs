import crypto from "node:crypto";
function assertJsonString(value){for(let i=0;i<value.length;i++){const c=value.charCodeAt(i);if(c>=0xD800&&c<=0xDBFF){if(i+1>=value.length){throw new TypeError("JCS_LONE_HIGH_SURROGATE");}const n=value.charCodeAt(i+1);if(n<0xDC00||n>0xDFFF){throw new TypeError("JCS_LONE_HIGH_SURROGATE");}i++;}else if(c>=0xDC00&&c<=0xDFFF){throw new TypeError("JCS_LONE_LOW_SURROGATE");}}}
function serialize(value){if(value===null)return "null";const type=typeof value;if(type==="string"){assertJsonString(value);return JSON.stringify(value);}if(type==="boolean")return value?"true":"false";if(type==="number"){if(!Number.isFinite(value)||Number.isNaN(value))throw new TypeError("JCS_NUMBER_INVALID");if(Object.is(value,-0))throw new TypeError("JCS_NEGATIVE_ZERO_REJECTED");return JSON.stringify(value);}if(type==="bigint"||type==="undefined"||type==="function"||type==="symbol")throw new TypeError(`JCS_UNSUPPORTED_TYPE:${type}`);if(Array.isArray(value))return "["+value.map(serialize).join(",")+"]";if(Object.getPrototypeOf(value)!==Object.prototype&&Object.getPrototypeOf(value)!==null)throw new TypeError("JCS_OBJECT_TYPE_INVALID");const keys=Object.keys(value).sort();return "{"+keys.map(k=>{assertJsonString(k);return JSON.stringify(k)+":"+serialize(value[k]);}).join(",")+"}";}
export function jcsCanonicalize(value){return serialize(value);}
export function jcsSha256(value){return crypto.createHash("sha256").update(Buffer.from(jcsCanonicalize(value),"utf8")).digest("hex");}
const sortingInput={"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"};
const expectedPrefix=["\r","1","\u0080","\u00f6","\u20ac","\ud83d\ude00","\ufb33"];const actualKeys=Object.keys(sortingInput).sort();
if(JSON.stringify(actualKeys)!==JSON.stringify(expectedPrefix))throw new Error("JCS_PROPERTY_SORT_TEST_FAILED");
if(jcsCanonicalize({b:1,a:2,nested:{z:true,a:null},arr:[{y:2,x:1}]})!=="{\"a\":2,\"arr\":[{\"x\":1,\"y\":2}],\"b\":1,\"nested\":{\"a\":null,\"z\":true}}")throw new Error("JCS_CANONICAL_OBJECT_TEST_FAILED");
let negativeZeroBlocked=false;try{jcsCanonicalize(-0);}catch(error){negativeZeroBlocked=error?.message==="JCS_NEGATIVE_ZERO_REJECTED";}if(!negativeZeroBlocked)throw new Error("JCS_NEGATIVE_ZERO_TEST_FAILED");
let nanBlocked=false;try{jcsCanonicalize(NaN);}catch(error){nanBlocked=error?.message==="JCS_NUMBER_INVALID";}if(!nanBlocked)throw new Error("JCS_NAN_TEST_FAILED");
let surrogateBlocked=false;try{jcsCanonicalize("\uD800");}catch(error){surrogateBlocked=error?.message==="JCS_LONE_HIGH_SURROGATE";}if(!surrogateBlocked)throw new Error("JCS_SURROGATE_TEST_FAILED");
console.log("=== JCS PROFILE V1.1 ===");
console.log("PROPERTY_SORT=PASS");
console.log("RECURSIVE_OBJECT_SORT=PASS");
console.log("NEGATIVE_ZERO_REJECTION=PASS");
console.log("NAN_REJECTION=PASS");
console.log("LONE_SURROGATE_REJECTION=PASS");
console.log("JCS_PROFILE_V1_1=PASS");
