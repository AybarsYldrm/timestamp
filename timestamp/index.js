"use strict";

/**
 * RFC3161 TSA - Node.js core-only (no external modules)
 * POST /tsa (application/timestamp-query) -> DER TimeStampResp (application/timestamp-reply)
 *
 * Fixes for OpenSSL 3.x:
 * - signingCertificateV2 encoded as minimal RFC5816 form:
 *   SigningCertificateV2 ::= SEQUENCE OF ESSCertIDv2
 *   ESSCertIDv2 ::= SEQUENCE { certHash OCTET STRING }  (sha256 default)
 * - signedAttrs [0] IMPLICIT embedding uses TLV parsing (no fragile slicing)
 * - certificates [0] IMPLICIT embedding uses TLV parsing
 * - Accuracy.millis [0] IMPLICIT INTEGER uses TLV parsing
 */

const http = require("http");
const crypto = require("crypto");
const fs = require("fs");

/* ===================== CONFIG ===================== */

const CFG = {
  listenHost: "0.0.0.0",
  listenPort: 3000,

  tsaKeyPath: "./tsa.key",
  tsaCertPath: "./tsa.crt",

  tsaPolicyOID: "1.3.6.1.4.1.99999.1.1",

  accuracySeconds: 1,
  accuracyMillis: 500,

  ordering: false,
  includeCertsInSignedData: true,

  serialFile: "./tsa_serial.bin"
};

/* ===================== OIDS ===================== */

const OID = {
  // RFC3161
  id_ct_TSTInfo: "1.2.840.113549.1.9.16.1.4",

  // CMS
  id_signedData: "1.2.840.113549.1.7.2",

  // Attributes
  contentType: "1.2.840.113549.1.9.3",
  messageDigest: "1.2.840.113549.1.9.4",

  // Hash
  sha256: "2.16.840.1.101.3.4.2.1",
  sha384: "2.16.840.1.101.3.4.2.2",
  sha512: "2.16.840.1.101.3.4.2.3",

  // RSA sig
  sha256WithRSAEncryption: "1.2.840.113549.1.1.11",

  // ESS
  signingCertificateV2: "1.2.840.113549.1.9.16.2.47"
};

/* ===================== DER ENCODER ===================== */

function concat(...bufs) {
  return Buffer.concat(bufs.filter(Boolean));
}

function derLen(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  let x = n;
  while (x > 0) { bytes.unshift(x & 0xff); x >>>= 8; }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function derTLV(tagByte, value) {
  return concat(Buffer.from([tagByte]), derLen(value.length), value);
}

function derNull() { return Buffer.from([0x05, 0x00]); }
function derBool(v) { return derTLV(0x01, Buffer.from([v ? 0xff : 0x00])); }

function derIntFromUnsignedBytes(bytes) {
  if (!Buffer.isBuffer(bytes)) bytes = Buffer.from(bytes);
  let b = bytes;
  while (b.length > 1 && b[0] === 0x00) b = b.slice(1);
  if (b[0] & 0x80) b = concat(Buffer.from([0x00]), b);
  return derTLV(0x02, b);
}

function derIntFromNumber(n) {
  if (n === 0) return derTLV(0x02, Buffer.from([0x00]));
  const bytes = [];
  let x = n >>> 0;
  while (x > 0) { bytes.unshift(x & 0xff); x >>>= 8; }
  return derIntFromUnsignedBytes(Buffer.from(bytes));
}

function derOctetString(buf) { return derTLV(0x04, Buffer.from(buf)); }

function derOID(oidStr) {
  const parts = oidStr.split(".").map(x => parseInt(x, 10));
  if (parts.length < 2) throw new Error("bad OID");
  const first = 40 * parts[0] + parts[1];
  const out = [first];
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i];
    const stack = [];
    stack.unshift(v & 0x7f);
    v >>>= 7;
    while (v > 0) {
      stack.unshift(0x80 | (v & 0x7f));
      v >>>= 7;
    }
    out.push(...stack);
  }
  return derTLV(0x06, Buffer.from(out));
}

function derSeq(...children) { return derTLV(0x30, concat(...children)); }

function derSetOfSorted(children) {
  const arr = children.slice().map(b => Buffer.from(b));
  arr.sort(Buffer.compare);
  return derTLV(0x31, concat(...arr));
}

function derExplicit(tagNumber, innerTLV) {
  return derTLV(0xa0 + tagNumber, Buffer.from(innerTLV));
}

function derImplicit(tagByte, innerValueBytes) {
  return concat(Buffer.from([tagByte]), derLen(innerValueBytes.length), innerValueBytes);
}

/* ===================== DER READER (minimal TLV) ===================== */

function readTLV(buf, offset = 0) {
  if (offset >= buf.length) throw new Error("TLV out of range");
  const tag = buf[offset];
  let lenByte = buf[offset + 1];
  if (lenByte === undefined) throw new Error("TLV truncated");
  let len, lenLen = 1;

  if ((lenByte & 0x80) === 0) {
    len = lenByte;
  } else {
    const n = lenByte & 0x7f;
    if (n === 0 || n > 4) throw new Error("TLV long length unsupported");
    if (offset + 2 + n > buf.length) throw new Error("TLV length truncated");
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | buf[offset + 2 + i];
    lenLen += n;
  }

  const headerLen = 1 + lenLen;
  const valueOff = offset + headerLen;
  const end = valueOff + len;
  if (end > buf.length) throw new Error("TLV value truncated");
  return { tag, len, headerLen, valueOff, end };
}

function readOIDValue(buf, valueOff, end) {
  const b = buf.slice(valueOff, end);
  if (b.length < 1) throw new Error("OID empty");
  const first = b[0];
  const p0 = Math.floor(first / 40);
  const p1 = first % 40;
  const parts = [p0, p1];
  let v = 0;
  for (let i = 1; i < b.length; i++) {
    v = (v << 7) | (b[i] & 0x7f);
    if ((b[i] & 0x80) === 0) { parts.push(v); v = 0; }
  }
  return parts.join(".");
}

function readIntegerValueBytes(buf, valueOff, end) {
  let b = buf.slice(valueOff, end);
  while (b.length > 1 && b[0] === 0x00) b = b.slice(1);
  return b;
}

/* ===================== TSA SERIAL ===================== */

function loadAndIncSerial() {
  let cur;
  try {
    const b = fs.readFileSync(CFG.serialFile);
    if (b.length !== 16) throw new Error("serialFile must be 16 bytes");
    cur = Buffer.from(b);
  } catch {
    cur = Buffer.alloc(16, 0);
    cur[15] = 1;
  }

  const next = Buffer.from(cur);
  for (let i = 15; i >= 0; i--) {
    next[i] = (next[i] + 1) & 0xff;
    if (next[i] !== 0) break;
  }

  const tmp = CFG.serialFile + ".tmp";
  fs.writeFileSync(tmp, next);
  fs.renameSync(tmp, CFG.serialFile);
  return cur;
}

/* ===================== CERT PARSE ===================== */

function pemToDer(pem) {
  const lines = pem.trim().split(/\r?\n/).filter(l => !l.startsWith("-----"));
  return Buffer.from(lines.join(""), "base64");
}

function loadPemChain(path) {
  const pem = fs.readFileSync(path, "utf8");
  const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  if (!blocks || blocks.length === 0) throw new Error("No certs found in " + path);
  return blocks;
}

function parseCertIssuerAndSerial(certDer) {
  const certSeq = readTLV(certDer, 0);
  if (certSeq.tag !== 0x30) throw new Error("cert not SEQUENCE");

  let off = certSeq.valueOff;
  const tbs = readTLV(certDer, off);
  if (tbs.tag !== 0x30) throw new Error("tbs not SEQUENCE");
  off = tbs.valueOff;

  let tlv = readTLV(certDer, off);
  if (tlv.tag === 0xa0) { // [0] EXPLICIT version
    off = tlv.end;
    tlv = readTLV(certDer, off);
  }

  if (tlv.tag !== 0x02) throw new Error("serial not INTEGER");
  const serialBytes = readIntegerValueBytes(certDer, tlv.valueOff, tlv.end);
  off = tlv.end;

  tlv = readTLV(certDer, off); // signature alg
  off = tlv.end;

  tlv = readTLV(certDer, off); // issuer Name
  if (tlv.tag !== 0x30) throw new Error("issuer not SEQUENCE");
  const issuerTLV = certDer.slice(off, tlv.end);

  return { serialBytes, issuerTLV };
}

/* ===================== RFC3161 PARSE ===================== */

function parseTimeStampReq(der) {
  const seq = readTLV(der, 0);
  if (seq.tag !== 0x30) throw new Error("TimeStampReq not SEQUENCE");
  let off = seq.valueOff;

  // version
  let tlv = readTLV(der, off);
  if (tlv.tag !== 0x02) throw new Error("version not INTEGER");
  off = tlv.end;

  // messageImprint
  tlv = readTLV(der, off);
  if (tlv.tag !== 0x30) throw new Error("messageImprint not SEQUENCE");
  let miOff = tlv.valueOff;

  const algId = readTLV(der, miOff);
  if (algId.tag !== 0x30) throw new Error("hashAlgorithm not SEQUENCE");
  let aoff = algId.valueOff;

  const algOidTLV = readTLV(der, aoff);
  if (algOidTLV.tag !== 0x06) throw new Error("hashAlgorithm OID missing");
  const hashAlgOID = readOIDValue(der, algOidTLV.valueOff, algOidTLV.end);

  miOff = algId.end;
  const hashed = readTLV(der, miOff);
  if (hashed.tag !== 0x04) throw new Error("hashedMessage not OCTET STRING");
  const hashedMessage = der.slice(hashed.valueOff, hashed.end);

  off = tlv.end;

  let reqPolicyOID = null;
  let nonceBytes = null;
  let certReq = false;

  while (off < seq.end) {
    tlv = readTLV(der, off);
    if (tlv.tag === 0x06) reqPolicyOID = readOIDValue(der, tlv.valueOff, tlv.end);
    else if (tlv.tag === 0x02) nonceBytes = readIntegerValueBytes(der, tlv.valueOff, tlv.end);
    else if (tlv.tag === 0x01) certReq = der[tlv.valueOff] !== 0x00;
    off = tlv.end;
  }

  const expected = (hashAlgOID === OID.sha256) ? 32 :
                   (hashAlgOID === OID.sha384) ? 48 :
                   (hashAlgOID === OID.sha512) ? 64 : null;
  if (expected && hashedMessage.length !== expected) {
    throw new Error(`hashedMessage length mismatch: got ${hashedMessage.length}, expected ${expected}`);
  }

  return { hashAlgOID, hashedMessage, reqPolicyOID, nonceBytes, certReq };
}

/* ===================== RFC3161 BUILD ===================== */

function generalizedTimeNowUTC() {
  const d = new Date();
  const yyyy = d.getUTCFullYear().toString().padStart(4, "0");
  const MM = (d.getUTCMonth() + 1).toString().padStart(2, "0");
  const dd = d.getUTCDate().toString().padStart(2, "0");
  const hh = d.getUTCHours().toString().padStart(2, "0");
  const mm = d.getUTCMinutes().toString().padStart(2, "0");
  const ss = d.getUTCSeconds().toString().padStart(2, "0");
  return derTLV(0x18, Buffer.from(`${yyyy}${MM}${dd}${hh}${mm}${ss}Z`, "ascii"));
}

function buildMessageImprint(hashAlgOID, hashedMessage) {
  const algId = derSeq(derOID(hashAlgOID), derNull());
  return derSeq(algId, derOctetString(hashedMessage));
}

function buildAccuracy(seconds, millis) {
  const parts = [];
  if (seconds != null) parts.push(derIntFromNumber(seconds));

  if (millis != null) {
    const intTLV = derIntFromNumber(millis);
    const intParsed = readTLV(intTLV, 0);
    if (intParsed.tag !== 0x02) throw new Error("millis int not INTEGER");
    const intValueBytes = intTLV.slice(intParsed.valueOff, intParsed.end);
    // millis [0] IMPLICIT INTEGER
    parts.push(derImplicit(0x80, intValueBytes));
  }

  return derSeq(...parts);
}

function buildTSTInfo({ policyOID, hashAlgOID, hashedMessage, serialBytes, nonceBytes }) {
  const version = derIntFromNumber(1);
  const policy = derOID(policyOID);
  const messageImprint = buildMessageImprint(hashAlgOID, hashedMessage);
  const serialNumber = derIntFromUnsignedBytes(serialBytes);
  const genTime = generalizedTimeNowUTC();

  const parts = [version, policy, messageImprint, serialNumber, genTime];

  if (CFG.accuracySeconds != null || CFG.accuracyMillis != null) {
    parts.push(buildAccuracy(CFG.accuracySeconds, CFG.accuracyMillis));
  }

  if (CFG.ordering) parts.push(derBool(true));
  if (nonceBytes) parts.push(derIntFromUnsignedBytes(nonceBytes));

  return derSeq(...parts);
}

/* ===================== CMS BUILD ===================== */

function algId(oid) {
  return derSeq(derOID(oid), derNull());
}

function buildSigningCertificateV2(certDerLeaf) {
  // SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2, policies [0] EXPLICIT OPTIONAL }
  // ESSCertIDv2 ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier DEFAULT sha256, hash OCTET STRING, issuerSerial OPTIONAL }

  const certHash = crypto.createHash("sha256").update(certDerLeaf).digest();

  // AlgorithmIdentifier(sha256) => SEQUENCE { OID } (params OMIT)
  const hashAlgId = derSeq(derOID(OID.sha256));

  const essCertIdV2 = derSeq(
    hashAlgId,
    derOctetString(certHash)
    // issuerSerial omitted
  );

  // certs: SEQUENCE OF ESSCertIDv2
  const certs = derSeq(essCertIdV2);

  // SigningCertificateV2: SEQUENCE { certs }
  return derSeq(certs);
}




function buildSignedAttributes(eContentTypeOID, eContentDER, certDerLeaf) {
  const md = crypto.createHash("sha256").update(eContentDER).digest();

  const attr_contentType = derSeq(
    derOID(OID.contentType),
    derSetOfSorted([derOID(eContentTypeOID)])
  );

  const attr_messageDigest = derSeq(
    derOID(OID.messageDigest),
    derSetOfSorted([derOctetString(md)])
  );

  const scv2 = buildSigningCertificateV2(certDerLeaf);
  const attr_signingCertV2 = derSeq(
    derOID(OID.signingCertificateV2),
    derSetOfSorted([scv2])
  );

  return derSetOfSorted([attr_contentType, attr_messageDigest, attr_signingCertV2]);
}

function buildSignerInfo({ certDerLeaf, signedAttrsSetDER }) {
  const { issuerTLV, serialBytes } = parseCertIssuerAndSerial(certDerLeaf);

  const version = derIntFromNumber(1);
  const sid = derSeq(issuerTLV, derIntFromUnsignedBytes(serialBytes));
  const digestAlg = algId(OID.sha256);

  // IMPLICIT [0] SignedAttributes: use TLV parser to extract SET value octets
  const saTLV = readTLV(signedAttrsSetDER, 0);
  if (saTLV.tag !== 0x31) throw new Error("signedAttrs is not DER SET");
  const signedAttrsValueOnly = signedAttrsSetDER.slice(saTLV.valueOff, saTLV.end);
  const signedAttrsField = derImplicit(0xa0, signedAttrsValueOnly);

  const sigAlg = algId(OID.sha256WithRSAEncryption);

  // Signature over DER-encoded SET OF signedAttrs
  const signature = crypto.sign(
    "RSA-SHA256",
    signedAttrsSetDER,
    { key: TSA.keyPem, padding: crypto.constants.RSA_PKCS1_PADDING }
  );

  return derSeq(
    version,
    sid,
    digestAlg,
    signedAttrsField,
    sigAlg,
    derOctetString(signature)
  );
}

function buildSignedData({ eContentTypeOID, eContentDER, certsDerList, signerInfoDER }) {
  const version = derIntFromNumber(3);

  const digestAlgorithms = derSetOfSorted([algId(OID.sha256)]);

  const eContent = derExplicit(0, derOctetString(eContentDER));
  const encapContentInfo = derSeq(derOID(eContentTypeOID), eContent);

  let certificatesField = null;
  if (CFG.includeCertsInSignedData && certsDerList && certsDerList.length) {
    const certSet = derSetOfSorted(certsDerList);
    const csTLV = readTLV(certSet, 0);
    if (csTLV.tag !== 0x31) throw new Error("certSet not DER SET");
    const certSetValueOnly = certSet.slice(csTLV.valueOff, csTLV.end);
    certificatesField = derImplicit(0xa0, certSetValueOnly);
  }

  const signerInfos = derSetOfSorted([signerInfoDER]);

  return derSeq(version, digestAlgorithms, encapContentInfo, certificatesField, signerInfos);
}

function buildContentInfoSignedData(signedDataDER) {
  return derSeq(
    derOID(OID.id_signedData),
    derExplicit(0, signedDataDER)
  );
}

/* ===================== RFC3161 RESPONSE ===================== */

function buildPKIStatusInfoGranted() {
  return derSeq(derIntFromNumber(0));
}

function buildTimeStampResp(timeStampTokenContentInfoDER) {
  return derSeq(buildPKIStatusInfoGranted(), timeStampTokenContentInfoDER);
}

/* ===================== LOAD MATERIAL ===================== */

const TSA = {
  keyPem: null,
  certPemBlocks: null,
  certDerList: null,
  leafDer: null
};

function loadTsaMaterial() {
  TSA.keyPem = fs.readFileSync(CFG.tsaKeyPath, "utf8");
  TSA.certPemBlocks = loadPemChain(CFG.tsaCertPath);
  TSA.certDerList = TSA.certPemBlocks.map(pem => pemToDer(pem));
  TSA.leafDer = TSA.certDerList[0];
  crypto.createPrivateKey(TSA.keyPem);
}

/* ===================== MAIN TSA PIPELINE ===================== */

function handleTsaRequest(tsqDer) {
  const req = parseTimeStampReq(tsqDer);

  const policy = req.reqPolicyOID || CFG.tsaPolicyOID;
  if (req.reqPolicyOID && req.reqPolicyOID !== CFG.tsaPolicyOID) {
    throw new Error(`Unsupported reqPolicy: ${req.reqPolicyOID}`);
  }

  const serialBytes = loadAndIncSerial();

  const tstInfoDER = buildTSTInfo({
    policyOID: policy,
    hashAlgOID: req.hashAlgOID,
    hashedMessage: req.hashedMessage,
    serialBytes,
    nonceBytes: req.nonceBytes
  });

  const signedAttrsSetDER = buildSignedAttributes(OID.id_ct_TSTInfo, tstInfoDER, TSA.leafDer);

  const signerInfoDER = buildSignerInfo({
    certDerLeaf: TSA.leafDer,
    signedAttrsSetDER
  });

  const signedDataDER = buildSignedData({
    eContentTypeOID: OID.id_ct_TSTInfo,
    eContentDER: tstInfoDER,
    certsDerList: TSA.certDerList,
    signerInfoDER
  });

  const tokenContentInfoDER = buildContentInfoSignedData(signedDataDER);

  return buildTimeStampResp(tokenContentInfoDER);
}

/* ===================== HTTP SERVER ===================== */

function bad(res, code, msg) {
  res.writeHead(code, { "content-type": "text/plain; charset=utf-8" });
  res.end(msg);
}

function okDER(res, der) {
  res.writeHead(200, {
    "content-type": "application/timestamp-reply",
    "content-length": der.length
  });
  res.end(der);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on("data", (c) => {
      total += c.length;
      if (total > 10 * 1024 * 1024) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

async function main() {
  loadTsaMaterial();

  const server = http.createServer(async (req, res) => {
    try {
      if (req.method === "GET" && req.url === "/") {
        res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
        res.end("RFC3161 TSA up. POST /tsa with DER TimeStampReq.\n");
        return;
      }

      if (req.method === "POST" && req.url === "/tsa") {
        const body = await readBody(req);
        const respDer = handleTsaRequest(body);
        okDER(res, respDer);
        return;
      }

      bad(res, 404, "not found");
    } catch (e) {
      bad(res, 400, "TSA error: " + (e && e.message ? e.message : String(e)));
    }
  });

  server.listen(CFG.listenPort, CFG.listenHost, () => {
    console.log(`[tsa] listening http://${CFG.listenHost}:${CFG.listenPort}`);
    console.log(`[tsa] key=${CFG.tsaKeyPath} cert=${CFG.tsaCertPath} policy=${CFG.tsaPolicyOID}`);
  });
}

main().catch((e) => {
  console.error("[fatal]", e);
  process.exit(1);
});
