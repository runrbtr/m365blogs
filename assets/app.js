(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var posts = [].slice.call(document.querySelectorAll(".post"));
  var days = [].slice.call(document.querySelectorAll(".day"));
  var haystack = posts.map(function (p) { return p.textContent.toLowerCase(); });
  var q = $("q"), countEl = $("count"), none = $("nomatch");
  var chips = [].slice.call(document.querySelectorAll(".fchip[data-id]"));
  var favchip = $("favchip");

  // ---- filter by blog (toggle chips; none selected = all), favorites, and search text
  function apply() {
    var terms = q.value.toLowerCase().split(/\s+/).filter(Boolean);
    var on = chips.filter(function (c) { return c.getAttribute("aria-pressed") === "true"; })
                  .map(function (c) { return c.getAttribute("data-id"); });
    var favOnly = favchip.getAttribute("aria-pressed") === "true";
    var shown = 0;
    posts.forEach(function (p, i) {
      var srcs = p.getAttribute("data-src").split(" ");
      var okSrc = !on.length || on.some(function (id) { return srcs.indexOf(id) !== -1; });
      var okText = terms.every(function (t) { return haystack[i].indexOf(t) !== -1; });
      p.hidden = !(okSrc && okText && (!favOnly || p.classList.contains("starred")));
      if (!p.hidden) shown++;
    });
    days.forEach(function (d) { d.hidden = !d.querySelector(".post:not([hidden])"); });
    none.hidden = shown > 0;
    none.textContent = favOnly && !terms.length && !on.length
      ? "No favorites yet. Click the star on a post to save it here." : "No posts match.";
    countEl.textContent = (terms.length || on.length || favOnly)
      ? "Showing " + shown + " of " + posts.length + " posts" : posts.length + " posts";
  }
  chips.forEach(function (c) {
    c.addEventListener("click", function () {
      c.setAttribute("aria-pressed", c.getAttribute("aria-pressed") === "true" ? "false" : "true");
      apply();
    });
  });
  favchip.addEventListener("click", function () {
    favchip.setAttribute("aria-pressed", favchip.getAttribute("aria-pressed") === "true" ? "false" : "true");
    apply();
  });
  q.addEventListener("input", apply);
  document.addEventListener("keydown", function (e) {
    var tag = document.activeElement && document.activeElement.tagName;
    if (e.key === "/" && !/input|textarea/i.test(tag)) { e.preventDefault(); q.focus(); }
    else if (e.key === "Escape" && document.activeElement === q) { q.value = ""; apply(); q.blur(); }
  });

  // ---- talking to the server (favorites and read marker belong to your account)
  var errBox = $("apierr");
  function showError(msg) { errBox.textContent = msg; errBox.hidden = !msg; }
  function api(path, body) {
    var opts = { credentials: "same-origin", cache: "no-store" };
    if (body) {
      opts.method = "POST";
      opts.headers = { "Content-Type": "application/json" };
      opts.body = JSON.stringify(body);
    }
    return fetch(path, opts).then(function (r) {
      if (r.status === 401) { location.href = "login"; throw new Error("signed out"); }
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    });
  }

  var favs = {}, lastRead = null, newest = "", loadedAt = 0, user = null;
  newest = posts.reduce(function (m, p) { var f = p.getAttribute("data-first"); return f > m ? f : m; }, "");

  function paintStars() {
    var n = 0;
    posts.forEach(function (p) {
      var on = !!favs[p.getAttribute("data-url")], b = p.querySelector(".star");
      p.classList.toggle("starred", on);
      if (on) n++;
      b.setAttribute("aria-pressed", on ? "true" : "false");
      var title = p.querySelector("h3").textContent;
      b.setAttribute("aria-label", user ? (on ? "Remove from favorites: " : "Save to favorites: ") + title : "Sign in to save to favorites: " + title);
      b.title = !user ? "Sign in to save favorites" : on ? "Remove from favorites" : "Save to favorites";
    });
    favchip.querySelector(".n").textContent = n;
  }

  var banner = $("unread"), unreadText = $("unread-text");
  function paintUnread() {
    var unread = lastRead ? posts.filter(function (p) { return p.getAttribute("data-first") > lastRead; }) : [];
    posts.forEach(function (p) { p.classList.toggle("unread", unread.indexOf(p) !== -1); });
    banner.hidden = !unread.length;
    if (unread.length) unreadText.textContent = unread.length + (unread.length === 1 ? " new post" : " new posts") + " since your last visit.";
  }

  function loadState() {
    return api("api/state").then(function (s) {
      favs = {};
      s.favorites.forEach(function (u) { favs[u] = 1; });
      lastRead = s.last_read;
      user = s.user;                                   // null for guests: they can read, but not save
      $("whoami").hidden = !user;
      $("logout").hidden = !user;
      $("guest").hidden = !!user;
      favchip.hidden = !user;
      if (user) $("whoami").textContent = "Signed in as " + user;
      else favchip.setAttribute("aria-pressed", "false");
      if (user && lastRead === null && newest) {            // first visit on this account: don't flag the whole history
        lastRead = newest;
        api("api/last-read", { value: newest }).catch(function () {});
      }
      loadedAt = Date.now();
      showError("");
      paintStars(); paintUnread(); apply();
    }).catch(function (e) {
      if (e.message !== "signed out") showError("Couldn't load your favorites. Check your connection and reload the page.");
    });
  }

  document.addEventListener("click", function (e) {
    var b = e.target.closest && e.target.closest(".star");
    if (!b) return;
    if (!user) { location.href = "login"; return; }     // favorites need an account
    var url = b.closest(".post").getAttribute("data-url"), on = !favs[url];
    if (on) favs[url] = 1; else delete favs[url];          // update at once, undo if the server refuses
    paintStars(); apply();
    api("api/favorite", { url: url, on: on }).then(function () { showError(""); }).catch(function (err) {
      if (err.message === "signed out") return;
      if (on) delete favs[url]; else favs[url] = 1;
      paintStars(); apply();
      showError("Couldn't save that favorite" + (err.message === "HTTP 409" ? " (limit reached)." : ". Check your connection and try again."));
    });
  });

  $("markread").addEventListener("click", function () {
    var previous = lastRead;
    lastRead = newest; paintUnread();
    api("api/last-read", { value: newest }).catch(function (err) {
      if (err.message === "signed out") return;
      lastRead = previous; paintUnread();
      showError("Couldn't save that. Check your connection and try again.");
    });
  });

  // Coming back to a tab that has been idle: pick up changes made on another device.
  document.addEventListener("visibilitychange", function () {
    if (document.visibilityState === "visible" && Date.now() - loadedAt > 60000) loadState();
  });

  loadState();

  // ---- warn when this page is old (the server rebuilds it, but this tab keeps what it loaded)
  var gen = new Date(document.documentElement.getAttribute("data-generated")), stale = $("stale");
  var hours = (Date.now() - gen.getTime()) / 3600000;
  if (hours > 12) {
    stale.hidden = false;
    stale.textContent = "This page was built " + (hours > 48 ? Math.floor(hours / 24) + " days" : Math.floor(hours) + " hours") +
      " ago. Reload to see newer posts.";
  }
})();
