const el=id=>document.getElementById(id), output=()=>el("result");
let urls=[];
function show(message) {
  for(const url of urls) URL.revokeObjectURL(url);
  urls=[];
  output().replaceChildren();
  const summary=document.createElement("p");
  summary.className="result-summary";
  summary.setAttribute("aria-live","polite");
  summary.textContent=message;
  output().append(summary);
}
function paragraph(text) {
  const p=document.createElement("p");
  p.textContent=text;
  output().append(p);
}
function run(callback) {
  el("run").onclick=async()=>{
    el("run").disabled=true;
    try{await callback();}catch(error){show(error.message);}
    finally{el("run").disabled=false;}
  };
}
function options(id,values,first=null) {
  const select=el(id);
  select.replaceChildren();
  if(first!==null) select.add(new Option(first,""));
  for(const value of values) select.add(new Option(value,value));
}
function table(rows) {
  const wrap=document.createElement("div"), data=document.createElement("table"), head=data.createTHead(), body=data.createTBody();
  wrap.className="table-wrap";
  rows.forEach((row,index)=>{
    const tr=(index?body:head).insertRow();
    for(const value of row){
      const cell=document.createElement(index?"td":"th");
      cell.textContent=String(value??"—");
      if(!index)cell.scope="col";
      tr.append(cell);
    }
  });
  wrap.append(data); output().append(wrap);
}
function bars(rows,description) {
  const figure=document.createElement("figure"), title=document.createElement("figcaption");
  title.textContent=description;
  figure.append(title);
  const max=rows.reduce((value,[,sample])=>Math.max(value,Math.abs(sample)),0)||1;
  for(const [label,value] of rows){
    const row=document.createElement("div"), name=document.createElement("span"), meter=document.createElement("meter"), amount=document.createElement("span");
    row.className="bar";
    name.textContent=label||"(blank)";
    amount.textContent=Number(value.toPrecision(8)).toLocaleString("en");
    meter.value=Math.abs(value);
    meter.max=max;
    meter.setAttribute("aria-label",name.textContent+" magnitude");
    row.append(name,meter,amount);
    figure.append(row);
  }
  output().append(figure);
}
function download(name,contents,type) {
  const url=URL.createObjectURL(new Blob([contents],{type}));
  urls.push(url);
  const anchor=document.createElement("a");
  anchor.className="button quiet export";
  anchor.textContent="Download "+name;
  anchor.download=name;
  anchor.href=url;
  output().append(anchor);
}
import {inspectMetadata} from "./tool.mjs";
let entities=[];
el("sample").onclick=()=>{
  el("source").value='<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">\n'+
  '  <md:EntityDescriptor entityID="https://identity.example.test">\n'+
  '    <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">\n'+
  '      <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://identity.example.test/sso"/>\n'+
  '    </md:IDPSSODescriptor>\n  </md:EntityDescriptor>\n'+
  '  <md:EntityDescriptor entityID="urn:sample:task-app">\n'+
  '    <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">\n'+
  '      <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://service.example.test/acs" index="0"/>\n'+
  '    </md:SPSSODescriptor>\n  </md:EntityDescriptor>\n</md:EntitiesDescriptor>';
};
function draw(index){
  const count=entities.reduce((sum,x)=>sum+x.endpoints.length,0);
  show(entities.length+" entities · "+count+" endpoints");
  const filters=document.createElement("select");
  filters.setAttribute("aria-label","Entity");
  for(const [i,item] of entities.entries())filters.add(new Option(item.id||"(Missing entity ID)",i));
  filters.value=String(index); filters.onchange=()=>draw(Number(filters.value));
  el("result").append(filters);
  const entity=entities[index];
  if(entity.issues.length) paragraph(entity.issues.join(" · "));
  if(entity.endpoints.length)table([["Role","Endpoint","Binding","Location","Notes"],...entity.endpoints.map(x=>[x.role,x.type,x.binding.split(":").at(-1),x.location,x.note])]);
  if(entity.certificates.length)table([["Role","Use","SHA-256","Notes"],...entity.certificates.map(x=>[x.role,x.use,x.sha256,x.note])]);
  download("saml-inventory.json",JSON.stringify(entities,null,2)+"\n","application/json");
}
run(async()=>{entities=await inspectMetadata(el("source").value,new DOMParser());draw(0);});
