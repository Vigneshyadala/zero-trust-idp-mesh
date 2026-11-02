(function () {
  "use strict";

  var slots = {
    service: document.getElementById("st-service"),
    issuer: document.getElementById("st-issuer"),
    ledger: document.getElementById("st-ledger"),
    key: document.getElementById("st-key")
  };

  function show(slot, text, ok) {
    if (!slot) { return; }
    slot.querySelector(".v").textContent = text;
    slot.classList.remove("ok", "bad");
    slot.classList.add(ok ? "ok" : "bad");
  }

  function get(path) {
    return fetch(path, { headers: { Accept: "application/json" }, cache: "no-store" })
      .then(function (r) {
        if (!r.ok) { throw new Error(String(r.status)); }
        return r.json();
      });
  }

  get("/health")
    .then(function (d) { show(slots.service, d.status === "ok" ? "running" : "degraded", d.status === "ok"); })
    .catch(function () { show(slots.service, "unreachable", false); });

  get("/.well-known/openid-configuration")
    .then(function (d) { show(slots.issuer, d.issuer, true); })
    .catch(function () { show(slots.issuer, "unavailable", false); });

  get("/ledger/chain")
    .then(function (d) { show(slots.ledger, d.length + " blocks, " + (d.valid ? "valid" : "INVALID"), d.valid === true); })
    .catch(function () { show(slots.ledger, "unavailable", false); });

  get("/jwks.json")
    .then(function (d) {
      var k = d.keys && d.keys[0];
      show(slots.key, k ? k.alg + ", kid " + String(k.kid).slice(0, 8) : "none", !!k);
    })
    .catch(function () { show(slots.key, "unavailable", false); });
})();