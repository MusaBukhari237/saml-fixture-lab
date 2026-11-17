import test from "node:test";
import assert from "node:assert/strict";
import {sanitizeXmlInput,endpointRisk,fingerprint} from "../docs/tool.mjs";
test("rejects DTDs and flags insecure or malformed locations",()=>{
  assert.throws(()=>sanitizeXmlInput('<!DOCTYPE test SYSTEM "https://example.test/dtd"><test/>'),/DTDs/);
  assert.equal(endpointRisk("https://example.test/endpoint"),"");
  assert.equal(endpointRisk("https://fixture:demo@example.test/endpoint"),"Credentials in URL");
  assert.equal(endpointRisk("http://example.test/endpoint"),"Non-HTTPS location");
  assert.equal(endpointRisk("not a URL"),"Invalid location URL");
});
test("fingerprints decoded bytes and rejects invalid base64",async()=>{
  assert.equal(await fingerprint("aG VsbG8="),"2C:F2:4D:BA:5F:B0:A3:0E:26:E8:3B:2A:C5:B9:E2:9E:1B:16:1E:5C:1F:A7:42:5E:73:04:33:62:93:8B:98:24");
  await assert.rejects(fingerprint("<test>"),/Malformed/);
});
