import {inspect} from "../src/engine.mjs";
import {evaluate} from "../src/cases.mjs";
import {evaluationReport} from "../src/analytics.mjs";
const results=evaluate(inspect), report=evaluationReport(results);
if(process.argv.includes("--json"))console.log(JSON.stringify(report,null,2));
else{console.table(report.cases);console.log(JSON.stringify(report.metrics,null,2));console.log("Curated synthetic evaluation; not a real-world detection rate.");}
