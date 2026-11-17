const metadataNS="urn:oasis:names:tc:SAML:2.0:metadata";
const signatureNS="http://www.w3.org/2000/09/xmldsig#";
const endpointKinds=new Set(["SingleSignOnService","AssertionConsumerService","SingleLogoutService","ArtifactResolutionService","DiscoveryResponse"]);
export function sanitizeXmlInput(xml) {
  if(typeof xml!=="string" || !xml.trim() || xml.length>1000000) throw Error("Paste XML below 1 MB.");
  if(/<!\s*(DOCTYPE|ENTITY)\b/i.test(xml)) throw Error("Metadata must omit DTDs and external entities.");
  return xml;
}
export function endpointRisk(value) {
  if(!value) return "Missing location";
  try {
    const url=new URL(value);
    if(url.protocol!=="https:") return "Non-HTTPS location";
    if(url.username||url.password) return "Credentials in URL";
    return "";
  } catch { return "Invalid location URL"; }
}
export async function fingerprint(base64) {
  const compact=base64.replace(/\s+/g,"");
  if(!compact || compact.length>25000 || !/^[A-Za-z0-9+/]+={0,2}$/.test(compact) || compact.length%4!==0) throw Error("Malformed certificate encoding");
  const bytes=Uint8Array.from(atob(compact),char=>char.charCodeAt(0));
  const hash=await crypto.subtle.digest("SHA-256",bytes);
  return [...new Uint8Array(hash)].map(byte=>byte.toString(16).padStart(2,"0")).join(":").toUpperCase();
}
export async function inspectMetadata(xml, parser) {
  const doc=parser.parseFromString(sanitizeXmlInput(xml),"application/xml");
  if(doc.getElementsByTagName("parsererror").length) throw Error("The XML is malformed.");
  const root=doc.documentElement;
  if(root.namespaceURI!==metadataNS||!["EntitiesDescriptor","EntityDescriptor"].includes(root.localName)) throw Error("Use a SAML metadata EntityDescriptor or EntitiesDescriptor document.");
  const entities=[...doc.getElementsByTagNameNS(metadataNS,"EntityDescriptor")];
  if(!entities.length||entities.length>100) throw Error("Use a document with between 1 and 100 entity descriptors.");
  const reports=[], identifiers=new Set();
  for(const entity of entities) {
    const id=entity.getAttribute("entityID")||"";
    const issues=[];
    if(!id) issues.push("Missing entity ID");
    if(id&&identifiers.has(id)) issues.push("Duplicate entity ID");
    if(id) identifiers.add(id);
    const roles=[...entity.children].filter(node=>node.namespaceURI===metadataNS&&["IDPSSODescriptor","SPSSODescriptor"].includes(node.localName));
    if(!roles.length) issues.push("No IdP or SP SSO role");
    const endpoints=[], certificates=[];
    for(const role of roles) {
      const name=role.localName==="IDPSSODescriptor"?"IdP":"SP";
      for(const node of role.children) {
        if(node.namespaceURI!==metadataNS) continue;
        if(endpointKinds.has(node.localName)) {
          const location=node.getAttribute("Location")||"", binding=node.getAttribute("Binding")||"";
          const risk=endpointRisk(location);
          endpoints.push({role:name,type:node.localName,binding,location,note:risk||(!binding?"Missing binding":"")});
        }
        if(node.localName==="KeyDescriptor") {
          const use=node.getAttribute("use")||"unspecified";
          for(const child of node.getElementsByTagNameNS(signatureNS,"X509Certificate")) {
            if(certificates.length>=50) throw Error("Use up to 50 certificate entries per entity.");
            try { certificates.push({role:name,use,sha256:await fingerprint(child.textContent||""),note:""}); }
            catch { certificates.push({role:name,use,sha256:"",note:"Malformed certificate encoding"}); }
          }
        }
      }
    }
    if(!certificates.length) issues.push("No X.509 certificate data found");
    reports.push({id,roles:roles.map(role=>role.localName==="IDPSSODescriptor"?"IdP":"SP"),issues,endpoints,certificates});
  }
  return reports;
}
