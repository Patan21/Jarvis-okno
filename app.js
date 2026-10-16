/* Okno Jarvisa v Telegrame (v0.9.34): nastavenie odtlačku a schválenie technického návrhu odtlačkom.
   - enrol:   ?a=enrol → kľúč ECDSA P-256 (WebCrypto) → súkromná časť (JWK d.x.y) za odtlačok (updateBiometricToken)
              → botovi len verejný kľúč SPKI (sendData {t:"enrol", v:1, pub}).
   - approve: ?a=approve&pid=&cid=&n=&exp= → odtlačok (authenticate vydá kľúč) → podpis presne
              "jarvis-approve|v1|<pid>|<cid>|<n>" (rovnaký tvar overuje Core, jarvis_core/telegram.py challenge_message)
              → sendData {t:"approve", v:1, pid, cid, sig} (podpis r||s 64 B, base64url).
   Okno nič nesťahuje ani neposiela do siete; výsledok ide len cez Telegram botovi (sendData funguje len z tlačidla
   klávesnice — preto ho Jarvis posiela ako tlačidlo dole pod písaním).
   v0.9.35: okno ukáže druh kroku a cieľ (&k=&t= z pevného slovníka Core — žiadny voľný text v adrese), odpočet platnosti
   výzvy a po podpise krátko zavibruje (HapticFeedback). */
(function () {
  "use strict";
  var tg = window.Telegram && window.Telegram.WebApp;
  var q = new URLSearchParams(window.location.search);
  var mode = q.get("a") || "";

  function $(id) { return document.getElementById(id); }
  function say(text, bad) { var m = $("msg"); m.textContent = text; m.className = bad ? "bad" : "ok"; }
  function bytesB64(buf) {
    var s = "", b = new Uint8Array(buf);
    for (var i = 0; i < b.length; i++) { s += String.fromCharCode(b[i]); }
    return window.btoa(s);
  }
  function b64url(buf) { return bytesB64(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
  function send(obj) { tg.sendData(JSON.stringify(obj)); }
  function buzz(kind) {
    try { if (tg.HapticFeedback) { tg.HapticFeedback.notificationOccurred(kind); } } catch (e) { /* bez vibrácie */ }
  }
  var ACT = { restart: "Reštart", apt_install: "Inštalácia systémového balíka", pip_install: "Inštalácia Python balíka",
              system_update: "Aktualizácia systému", reboot: "Reštart Mini", deploy: "Nasadenie novej verzie",
              rollback: "Návrat na predchádzajúcu verziu", exec: "Príkaz vo vývojárskom režime", skill: "Nový skill",
              other: "Technický krok" };
  var TGT = { "jarvis-core": "Jarvis Core", "jarvis-gateway": "Gateway", "jarvis-exec": "vývojársky executor",
              "searxng": "vyhľadávanie", "jarvis-voice": "hlas", "jarvis-speech": "prepis reči", "jarvis-telegram": "Telegram" };
  function own(o, k) { return Object.prototype.hasOwnProperty.call(o, k); }
  function label() {
    var k = q.get("k") || "", t = q.get("t") || "";
    var a = own(ACT, k) ? ACT[k] : "Technický krok";
    return (k === "restart" && own(TGT, t)) ? a + ": " + TGT[t] + " (" + t + ")" : a;
  }

  if (!tg || !tg.platform || tg.platform === "unknown") {
    $("what").textContent = "Toto okno funguje len v Telegrame — otvor ho tlačidlom od Jarvisa.";
    return;
  }
  tg.ready();
  tg.expand();
  if (!tg.isVersionAtLeast("7.2") || !tg.BiometricManager) {
    say("Aktualizuj Telegram — schválenie odtlačkom potrebuje novšiu verziu.", true);
    return;
  }
  if (!window.crypto || !window.crypto.subtle) {
    say("Toto zariadenie nepodporuje bezpečné kľúče (WebCrypto).", true);
    return;
  }
  var bm = tg.BiometricManager;
  $("cancel").hidden = false;
  $("cancel").onclick = function () { send({ t: "cancel", v: 1 }); };

  bm.init(function () {
    if (!bm.isBiometricAvailable) {
      say("Na tomto zariadení odtlačok nie je (napr. Telegram na počítači). Schváľ na mobile alebo v Gateway.", true);
      return;
    }
    if (mode === "enrol") { enrol(); } else if (mode === "approve") { approve(); } else { say("Neznáma požiadavka.", true); }
  });

  function enrol() {
    $("what").textContent = "Nastavenie odtlačku pre technické schválenia (reštart, inštalácia, nasadenie).";
    var go = $("go");
    go.textContent = "Nastaviť odtlačok";
    go.hidden = false;
    go.onclick = function () {
      go.disabled = true;
      say("");
      bm.requestAccess({ reason: "Jarvis: schvaľovanie technických krokov odtlačkom" }, function (granted) {
        if (!granted) {
          go.disabled = false;
          say("Prístup k odtlačku nebol povolený — povoľ ho v nastaveniach bota a skús znova.", true);
          return;
        }
        var kp;
        window.crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])
          .then(function (pair) {
            kp = pair;
            return Promise.all([window.crypto.subtle.exportKey("jwk", kp.privateKey), window.crypto.subtle.exportKey("spki", kp.publicKey)]);
          })
          .then(function (r) {
            var jwk = r[0];
            bm.updateBiometricToken([jwk.d, jwk.x, jwk.y].join("."), function (ok) {
              if (!ok) { go.disabled = false; buzz("error"); say("Kľúč sa nepodarilo uložiť za odtlačok.", true); return; }
              buzz("success");
              send({ t: "enrol", v: 1, pub: bytesB64(r[1]) });
            });
          })
          .catch(function () { go.disabled = false; say("Kľúč sa nepodarilo vytvoriť.", true); });
      });
    };
  }

  function approve() {
    var pid = q.get("pid") || "", cid = q.get("cid") || "", n = q.get("n") || "";
    var exp = Number(q.get("exp") || 0);
    if (!/^\d{1,9}$/.test(pid) || !/^[A-Za-z0-9_-]{8,64}$/.test(cid) || !/^[A-Za-z0-9_-]{8,64}$/.test(n)) {
      say("Neplatná výzva — klepni znova na „Schváliť odtlačkom“ v Telegrame.", true);
      return;
    }
    $("what").textContent = label() + " · návrh #" + pid;
    $("detail").textContent = "Ten istý krok je aj na karte v Telegrame nad tlačidlom.";
    if (!bm.isBiometricTokenSaved) {
      say("Odtlačok na tomto mobile nie je nastavený — Gateway → Osoby → Telegram → Odtlačok.", true);
      return;
    }
    var go = $("go");
    go.textContent = "Schváliť odtlačkom";
    go.hidden = false;
    var timer = 0;
    function tick() {   // v0.9.35: odpočet platnosti výzvy (5 min)
      if (!exp) { return; }
      var left = Math.max(0, Math.round(exp - Date.now() / 1000));
      $("detail").textContent = left > 0 ? "Platí ešte " + Math.floor(left / 60) + ":" + ("0" + (left % 60)).slice(-2) +
        " · ten istý krok je aj na karte v Telegrame." : "Výzva vypršala — klepni znova na „Schváliť odtlačkom“ v Telegrame.";
      if (left <= 0 && timer) { window.clearInterval(timer); go.disabled = true; }
    }
    tick();
    timer = window.setInterval(tick, 1000);
    go.onclick = function () {
      if (exp && Date.now() / 1000 > exp) { say("Výzva vypršala — klepni znova na „Schváliť odtlačkom“ v Telegrame.", true); return; }
      go.disabled = true;
      say("");
      bm.authenticate({ reason: "Jarvis: schváliť návrh #" + pid }, function (ok, token) {
        if (!ok || !token) { go.disabled = false; buzz("error"); say("Overenie zrušené.", true); return; }
        var p = String(token).split(".");
        if (p.length !== 3) { go.disabled = false; say("Uložený kľúč je poškodený — nastav odtlačok znova.", true); return; }
        window.crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", d: p[0], x: p[1], y: p[2], ext: false },
          { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"])
          .then(function (key) {
            var msg = new TextEncoder().encode("jarvis-approve|v1|" + pid + "|" + cid + "|" + n);
            return window.crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, msg);
          })
          .then(function (sig) { buzz("success"); send({ t: "approve", v: 1, pid: Number(pid), cid: cid, sig: b64url(sig) }); })
          .catch(function () { go.disabled = false; say("Podpis sa nepodaril.", true); });
      });
    };
  }
})();
