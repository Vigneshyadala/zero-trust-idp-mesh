(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };
  var OUTCOMES = ["success", "blocked", "error"];
  var key = "";
  var timer = null;

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text !== undefined) { node.textContent = text; }
    return node;
  }

  function api(path) {
    return fetch(path, { headers: { "X-Admin-Key": key, Accept: "application/json" }, cache: "no-store" })
      .then(function (r) {
        if (!r.ok) {
          throw new Error(
            r.status === 401 ? "Invalid admin key"
            : r.status === 503 ? "Admin disabled: set IDP_ADMIN_KEY on the server"
            : r.status === 429 ? "Too many requests: wait a minute and try again"
            : "Request failed (" + r.status + ")"
          );
        }
        return r.json();
      });
  }

  function render(summary, events) {
    var cards = $("cards");
    cards.replaceChildren();
    var names = Object.keys(summary.counts);
    if (!names.length) { cards.appendChild(el("p", "empty", "No events yet.")); }
    names.forEach(function (name) {
      var card = el("div", "card");
      card.appendChild(el("b", "", String(summary.counts[name])));
      card.appendChild(el("span", "", name));
      cards.appendChild(card);
    });

    var body = $("rows");
    body.replaceChildren();
    events.events.forEach(function (e) {
      var tr = el("tr");
      tr.appendChild(el("td", "", new Date(e.ts * 1000).toLocaleString()));
      tr.appendChild(el("td", "", e.event));
      var outcomeCell = el("td");
      var known = OUTCOMES.indexOf(e.outcome) >= 0 ? e.outcome : "other";
      outcomeCell.appendChild(el("span", "badge " + known, e.outcome));
      tr.appendChild(outcomeCell);
      tr.appendChild(el("td", "", e.subject || ""));
      tr.appendChild(el("td", "", e.client_id || ""));
      tr.appendChild(el("td", "", e.ip || ""));
      tr.appendChild(el("td", "mono", JSON.stringify(e.detail)));
      body.appendChild(tr);
    });
    $("updated").textContent = "Updated " + new Date().toLocaleTimeString();
  }

  function stop() {
    if (timer !== null) { clearInterval(timer); timer = null; }
  }

  function refresh() {
    $("msg").textContent = "";
    var outcome = $("outcome").value;
    var q = outcome ? "&outcome=" + encodeURIComponent(outcome) : "";
    return Promise.all([api("/admin/api/summary"), api("/admin/api/events?limit=100" + q)])
      .then(function (results) { render(results[0], results[1]); return true; })
      .catch(function (err) { $("msg").textContent = err.message; stop(); return false; });
  }

  function lock() {
    stop();
    key = "";
    $("key").value = "";
    $("cards").replaceChildren();
    $("rows").replaceChildren();
    $("updated").textContent = "";
    $("msg").textContent = "";
  }

  $("load").addEventListener("click", function () {
    key = $("key").value;
    stop();
    if (!key) { $("msg").textContent = "Enter the admin key first"; return; }
    refresh().then(function (ok) {
      if (ok && timer === null) { timer = setInterval(refresh, 10000); }
    });
  });
  $("lock").addEventListener("click", lock);
  $("outcome").addEventListener("change", function () { if (key) { refresh(); } });
})();