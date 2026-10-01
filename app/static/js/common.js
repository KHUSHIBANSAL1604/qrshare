/* Shared helpers: config reading, toasts, copy buttons, live countdowns.
   Loaded on every page. No inline handlers anywhere -- the CSP forbids them. */
(function () {
  "use strict";

  /** Read a server-rendered <script type="application/json"> block. */
  function readConfig(id) {
    var node = document.getElementById(id);
    if (!node) return {};
    try {
      return JSON.parse(node.textContent) || {};
    } catch (err) {
      return {};
    }
  }

  /** Brief confirmation message at the bottom of the screen. */
  var toastTimer = null;
  function toast(message) {
    var el = document.getElementById("toast");
    if (!el) return;
    el.textContent = message;
    el.classList.add("is-visible");
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(function () {
      el.classList.remove("is-visible");
    }, 2200);
  }

  function humanSize(bytes) {
    var units = ["B", "KB", "MB", "GB"];
    var size = Number(bytes) || 0;
    for (var i = 0; i < units.length; i++) {
      if (size < 1024 || i === units.length - 1) {
        return (i === 0 ? Math.round(size) : size.toFixed(1)) + " " + units[i];
      }
      size /= 1024;
    }
    return size + " GB";
  }

  function humanDuration(seconds) {
    var s = Math.max(0, Math.floor(seconds));
    if (s < 60) return s + "s";
    var m = Math.floor(s / 60);
    var rs = s % 60;
    if (m < 60) return m + "m " + String(rs).padStart(2, "0") + "s";
    var h = Math.floor(m / 60);
    var rm = m % 60;
    if (h < 24) return h + "h " + String(rm).padStart(2, "0") + "m";
    return Math.floor(h / 24) + "d " + String(h % 24).padStart(2, "0") + "h";
  }

  /** Show an element's `hidden` state without touching inline styles. */
  function show(el, visible) {
    if (el) el.hidden = !visible;
  }

  function setError(boxId, textId, message) {
    var box = document.getElementById(boxId);
    var text = document.getElementById(textId);
    if (!box || !text) return;
    if (message) {
      text.textContent = message;
      box.hidden = false;
    } else {
      box.hidden = true;
    }
  }

  /** Clipboard with a fallback for non-secure origins (plain http on a LAN). */
  function copyText(value) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(value);
    }
    return new Promise(function (resolve, reject) {
      var helper = document.createElement("textarea");
      helper.value = value;
      helper.setAttribute("readonly", "readonly");
      helper.classList.add("sr-only");
      document.body.appendChild(helper);
      helper.select();
      var ok = false;
      try {
        ok = document.execCommand("copy");
      } catch (err) {
        ok = false;
      }
      document.body.removeChild(helper);
      ok ? resolve() : reject(new Error("copy failed"));
    });
  }

  /** Wire every [data-copy="#target"] button on the page. */
  function initCopyButtons() {
    document.querySelectorAll("[data-copy]").forEach(function (button) {
      button.addEventListener("click", function () {
        var target = document.querySelector(button.getAttribute("data-copy"));
        if (!target) return;
        copyText(target.value || target.textContent).then(
          function () {
            toast("Copied to clipboard");
            target.select && target.select();
          },
          function () {
            toast("Press Ctrl+C to copy");
            target.select && target.select();
          }
        );
      });
    });
  }

  /**
   * Tick a countdown element once a second.
   * `onExpire` fires exactly once when the deadline passes.
   */
  function startCountdown(el, isoDeadline, onExpire) {
    if (!el || !isoDeadline) return function () {};
    var deadline = new Date(isoDeadline).getTime();
    if (isNaN(deadline)) return function () {};
    var fired = false;
    var statEl = el.closest(".stat");

    function tick() {
      var remaining = Math.floor((deadline - Date.now()) / 1000);
      el.textContent = remaining > 0 ? humanDuration(remaining) : "Expired";
      if (statEl) statEl.classList.toggle("is-urgent", remaining > 0 && remaining < 300);
      if (remaining <= 0 && !fired) {
        fired = true;
        if (typeof onExpire === "function") onExpire();
      }
    }

    tick();
    var handle = window.setInterval(tick, 1000);
    return function stop() {
      window.clearInterval(handle);
    };
  }

  /** Render every <time datetime="..."> in the visitor's own locale. */
  function localiseTimes() {
    document.querySelectorAll("time[datetime]").forEach(function (node) {
      var when = new Date(node.getAttribute("datetime"));
      if (isNaN(when.getTime())) return;
      node.textContent = when.toLocaleString(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      });
      node.title = when.toString();
    });
  }

  window.QRShare = {
    readConfig: readConfig,
    toast: toast,
    humanSize: humanSize,
    humanDuration: humanDuration,
    show: show,
    setError: setError,
    copyText: copyText,
    startCountdown: startCountdown,
  };

  document.addEventListener("DOMContentLoaded", function () {
    initCopyButtons();
    localiseTimes();
  });
})();
