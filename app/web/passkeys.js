"use strict";

const STORAGE_KEY = "zt-idp-demo-identity";
const params = new URLSearchParams(window.location.search);
const requestId = params.get("request_id");

const els = {
  did: document.getElementById("did"),
  create: document.getElementById("create-identity"),
  register: document.getElementById("register"),
  login: document.getElementById("login"),
  loginSection: document.getElementById("login-section"),
  noRequest: document.getElementById("no-request"),
  log: document.getElementById("log"),
};

function log(message) {
  els.log.textContent += message + "\n";
}

// ---- base64url / base58 helpers --------------------------------------------

function b64urlEncode(buffer) {
  let binary = "";
  new Uint8Array(buffer).forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(text) {
  let value = text.replace(/-/g, "+").replace(/_/g, "/");
  while (value.length % 4) value += "=";
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function b58encode(bytes) {
  let n = 0n;
  for (const byte of bytes) n = (n << 8n) | BigInt(byte);
  let out = "";
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const byte of bytes) {
    if (byte === 0) out = "1" + out; else break;
  }
  return out;
}

// ---- DID identity (Ed25519 via WebCrypto) -----------------------------------
// Demo only: the private key is kept as a JWK in this browser's localStorage.

function loadIdentity() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY));
  } catch (error) {
    return null;
  }
}

async function createIdentity() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const multicodec = new Uint8Array(34);
  multicodec[0] = 0xed;
  multicodec[1] = 0x01;
  multicodec.set(raw, 2);
  const did = "did:key:z" + b58encode(multicodec);
  const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const identity = { did, jwk };
  localStorage.setItem(STORAGE_KEY, JSON.stringify(identity));
  return identity;
}

async function signWithIdentity(identity, message) {
  const key = await crypto.subtle.importKey("jwk", identity.jwk, { name: "Ed25519" }, false, ["sign"]);
  const signature = await crypto.subtle.sign({ name: "Ed25519" }, key, new TextEncoder().encode(message));
  return b64urlEncode(signature);
}

// ---- WebAuthn JSON <-> browser objects ---------------------------------------

function creationOptions(o) {
  return {
    ...o,
    challenge: b64urlDecode(o.challenge),
    user: { ...o.user, id: b64urlDecode(o.user.id) },
    excludeCredentials: (o.excludeCredentials || []).map((c) => ({ ...c, id: b64urlDecode(c.id) })),
  };
}

function requestOptions(o) {
  return {
    ...o,
    challenge: b64urlDecode(o.challenge),
    allowCredentials: (o.allowCredentials || []).map((c) => ({ ...c, id: b64urlDecode(c.id) })),
  };
}

function registrationToJson(credential) {
  const json = {
    id: credential.id,
    rawId: b64urlEncode(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: b64urlEncode(credential.response.clientDataJSON),
      attestationObject: b64urlEncode(credential.response.attestationObject),
    },
  };
  if (credential.response.getTransports) json.response.transports = credential.response.getTransports();
  if (credential.authenticatorAttachment) json.authenticatorAttachment = credential.authenticatorAttachment;
  return json;
}

function assertionToJson(credential) {
  const json = {
    id: credential.id,
    rawId: b64urlEncode(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: b64urlEncode(credential.response.clientDataJSON),
      authenticatorData: b64urlEncode(credential.response.authenticatorData),
      signature: b64urlEncode(credential.response.signature),
    },
  };
  if (credential.response.userHandle) json.response.userHandle = b64urlEncode(credential.response.userHandle);
  if (credential.authenticatorAttachment) json.authenticatorAttachment = credential.authenticatorAttachment;
  return json;
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || ("HTTP " + response.status));
  return data;
}

// ---- actions -----------------------------------------------------------------

async function run(button, action) {
  button.disabled = true;
  try {
    await action();
  } catch (error) {
    log("Error: " + (error && error.message ? error.message : error));
  } finally {
    button.disabled = false;
  }
}

els.create.addEventListener("click", () => run(els.create, async () => {
  if (!window.crypto || !crypto.subtle) throw new Error("WebCrypto is not available (use http://localhost)");
  let identity;
  try {
    identity = await createIdentity();
  } catch (error) {
    throw new Error("This browser cannot create Ed25519 keys; update Chrome/Edge. (" + error.message + ")");
  }
  els.did.value = identity.did;
  log("Created identity " + identity.did);
}));

els.register.addEventListener("click", () => run(els.register, async () => {
  const identity = loadIdentity();
  const did = els.did.value.trim();
  if (!identity || identity.did !== did) {
    throw new Error("This browser does not hold the key for that DID. Create a new identity first.");
  }
  log("Requesting registration options...");
  const start = await postJson("/webauthn/register/options", { did });
  const credential = await navigator.credentials.create({ publicKey: creationOptions(start.options) });
  const didProof = await signWithIdentity(identity, "webauthn-register:" + did + ":" + start.options.challenge);
  const result = await postJson("/webauthn/register/verify", {
    ceremony_id: start.ceremony_id,
    credential: registrationToJson(credential),
    did_proof: didProof,
  });
  log("Passkey registered for " + result.did);
}));

els.login.addEventListener("click", () => run(els.login, async () => {
  const did = els.did.value.trim();
  if (!did) throw new Error("Enter or create a DID first.");
  log("Requesting login options...");
  const start = await postJson("/webauthn/login/options", { did, request_id: requestId });
  const assertion = await navigator.credentials.get({ publicKey: requestOptions(start.options) });
  const result = await postJson("/webauthn/login/verify", {
    ceremony_id: start.ceremony_id,
    credential: assertionToJson(assertion),
  });
  log("Signed in. Redirecting to the application...");
  window.location.assign(result.redirect_to);
}));

(function init() {
  const identity = loadIdentity();
  if (identity) els.did.value = identity.did;
  (requestId ? els.loginSection : els.noRequest).hidden = false;
  if (!window.PublicKeyCredential) log("This browser does not support WebAuthn.");
})();
