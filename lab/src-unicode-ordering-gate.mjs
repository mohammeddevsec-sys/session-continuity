import { canonicalStringify } from '../src/core/canonical.js';

let pass=0;
let fail=0;
function check(name,cond){
  if(cond){ console.log(name+'=PASS'); pass++; }
  else { console.log(name+'=FAIL'); fail++; }
}

try {
  const out=canonicalStringify({b:1,a:2});
  check('SIMPLE_KEY_SORT', out==='{"a":2,"b":1}');
} catch(e){ check('SIMPLE_KEY_SORT', false); }

try {
  const out=canonicalStringify({b:1,a:2,nested:{z:true,a:null},arr:[{y:2,x:1}]});
  check('NESTED_OBJECT_SORT', out==='{"a":2,"arr":[{"x":1,"y":2}],"b":1,"nested":{"a":null,"z":true}}');
} catch(e){ check('NESTED_OBJECT_SORT', false); }

try {
  const input={};
  input['\u20AC']='Euro';
  input['\r']='CR';
  input['\uFB33']='Hebrew';
  input['1']='One';
  input['\uD83D\uDE00']='Emoji';
  input['\u0080']='Control';
  input['\u00F6']='ouml';
  const sorted=Object.keys(input).sort();
  const expected=['\r','1','\u0080','\u00F6','\u20AC','\uD83D\uDE00','\uFB33'];
  check('UTF16_PROPERTY_ORDER', JSON.stringify(sorted)===JSON.stringify(expected));
} catch(e){ check('UTF16_PROPERTY_ORDER', false); }

try {
  const input={};
  input['\u20AC']='Euro';
  input['\r']='CR';
  input['\u00F6']='ouml';
  const out=canonicalStringify(input);
  const keys=Object.keys(JSON.parse(out));
  const expected=['\r','\u00F6','\u20AC'];
  check('CANONICAL_UTF16_ORDER', JSON.stringify(keys)===JSON.stringify(expected));
} catch(e){ check('CANONICAL_UTF16_ORDER', false); }

console.log('PASS_COUNT='+pass);
console.log('FAIL_COUNT='+fail);
console.log('UNICODE_ORDERING_GATE='+(fail===0?'PASS':'FAIL'));
