const fs = require("fs");
const startline = 30; //line which u want to see
// fs.readFile("./pixi-new.sarif" /*file*/, (err, inputD /*inpuutD is basically the indiv letter*/) => {
//   if (err) throw err;
//   inputline = inputD.toString().split("\n") //to make it line by line
//   console.log(inputline[startline-1]);
// });

const sarifFiles = "./pixi-new.sarif";

let fileString = fs.readFileSync(`${sarifFiles}`, "utf8");
let sarifFile = JSON.parse(fileString);
let xssdict = {};

function removeDuplicates(arr) {
  return arr.filter((item, index) => arr.indexOf(item) === index);
}

function breakdownsarif() {
  let ruletype = [];
  let combine_xss_data = [];
  for (let i = 0; i < sarifFile["runs"][0]["results"].length; i++) {
    ruletype.push(sarifFile["runs"][0]["results"][i]["rule"]["id"]);
    combine_xss_data.push(sarifFile["runs"][0]["results"][i]);
  }
  ruletype = removeDuplicates(ruletype);
  for (let i = 0; i < ruletype.length; i++) {
    let indiv_xss_data = [];
    for (let o = 0; o < combine_xss_data.length; o++) {
      if (combine_xss_data[o]["rule"]["id"] == ruletype[i]) {
        indiv_xss_data.push(combine_xss_data[o]);
      }
    }
    xssdict[ruletype[i]] = indiv_xss_data;
  }
}

function storedxssattack() {
  let storedxssdict = xssdict["js/stored-xss"];
  let storedcodelocator = [];
  try {
    storedxssdict.length;
  } catch (TypeError) {
    console.log("storedxssattack fail");
    return;
  }
  // console.log("storedxssattack success")
  for (let i = 0; i < storedxssdict.length; i++) {
    // console.log(reflectedxssdict[i]["locations"][0])
    let locodata = [];
    for (let x = 0;x <storedxssdict[i]["codeFlows"][0]["threadFlows"][0]["locations"].length;x++) {
      locodata.push(
        storedxssdict[i]["codeFlows"][0]["threadFlows"][0]["locations"][x]["location"]["physicalLocation"]["artifactLocation"]["uri"]
      );
      locodata.push(
        readfiledata(storedxssdict[i]["codeFlows"][0]["threadFlows"][0]["locations"][x]["location"]["physicalLocation"]["artifactLocation"]["uri"],storedxssdict[i]["codeFlows"][0]["threadFlows"][0]["locations"][x]["location"]["physicalLocation"]["region"]["startLine"])
      );
    }
    storedcodelocator.push(removeDuplicates(locodata));
  }
  console.log(storedcodelocator);
}
function reflectedxssattack() {
  let reflectedxssdict = xssdict["js/reflected-xss"];
  let reflectedcodelocator = [];
  try {
    reflectedxssdict.length;
  } catch (TypeError) {
    console.log("reflectedxssattack fail");
    return;
  }
  // console.log("reflectedxssattack success")
  for (let i = 0; i < reflectedxssdict.length; i++) {
    let locodata = [];
    for (let x = 0;x <reflectedxssdict[i]["codeFlows"][0]["threadFlows"][0]["locations"].length;x++) {
      locodata.push(
        reflectedxssdict[i]["codeFlows"][0]["threadFlows"][0]["locations"][x]["location"]["physicalLocation"]["artifactLocation"]["uri"]
      );
      locodata.push(
        readfiledata(reflectedxssdict[i]["codeFlows"][0]["threadFlows"][0]["locations"][x]["location"]["physicalLocation"]["artifactLocation"]["uri"],reflectedxssdict[i]["codeFlows"][0]["threadFlows"][0]["locations"][x]["location"]["physicalLocation"]["region"]["startLine"])
      );
    }
    reflectedcodelocator.push(removeDuplicates(locodata));
  }
  console.log(reflectedcodelocator);
}
function domxssattack() {
  let domxssdict = xssdict["js/xss-through-dom"];
  let domcodelocator = [];
  try {
    domxssdict.length;
  } catch (TypeError) {
    console.log("domxssattack fail");
    return;
  }
  // console.log("domxssattack success")
  for (let i = 0; i < domxssdict.length; i++) {
    let locodata = [];
    for (let x = 0;x < domxssdict[i]["codeFlows"][0]["threadFlows"][0]["locations"].length;x++) {
      locodata.push(
        domxssdict[i]["codeFlows"][0]["threadFlows"][0]["locations"][x]["location"]["physicalLocation"]["artifactLocation"]["uri"]
      );

      locodata.push(
        readfiledata(domxssdict[i]["codeFlows"][0]["threadFlows"][0]["locations"][x]["location"]["physicalLocation"]["artifactLocation"]["uri"],domxssdict[i]["codeFlows"][0]["threadFlows"][0]["locations"][x]["location"]["physicalLocation"]["region"]["startLine"])
      );
    }
    domcodelocator.push(removeDuplicates(locodata));
  }
  console.log(domcodelocator);
}
function readfiledata(filepath,line){
  var text = fs.readFileSync(filepath).toString().split('\n');
  return (text[line-1])
}



breakdownsarif();
// storedxssattack()
// reflectedxssattack()
domxssattack();



