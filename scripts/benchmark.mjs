import {inspect} from "../src/engine.mjs";
import {evaluate} from "../src/cases.mjs";
const results=evaluate(inspect);
console.table(results.map(({label,expected,actual})=>({label,expected,actual,match:expected===actual})));
const match=results.filter(r=>r.actual===r.expected).length;
const missedBlocks=results.filter(r=>r.expected==="block"&&r.actual!=="block").length;
const falseBlocks=results.filter(r=>r.expected==="allow"&&r.actual==="block").length;
console.log(JSON.stringify({cases:results.length,exactMatches:match,missedBlocks,falseBlocks},null,2));
console.log("Curated synthetic evaluation; not a real-world detection rate.");
