/* Sender's manage page: live countdown, polled status, cancel. */
(function () {
  "use strict";

  var Q = window.QRShare;
  var cfg = Q.readConfig("share-config");

  var countdownEl = document.getElementById("countdown");
  var badgeEl = document.getElementById("status-badge");
  var countEl = document.getElementById("download-count");
  var cancelBtn = document.getElementById("cancel-share");

  var BADGE_CLASS = {
    active: "badge badge--ok",
    expired: "badge badge--muted",
    used: "badge badge--warn",
    deleted: "badge badge--danger",
  };

  var stopCountdown = Q.startCountdown(countdownEl, cfg.expiresAt, function () {
    render({ status: "expired" });
  });

  function render(info) {
    if (info.downloads !== undefined && countEl) {
      countEl.textContent = info.downloads;
    }
    if (info.status && badgeEl) {
      badgeEl.className = BADGE_CLASS[info.status] || "badge badge--muted";
      badgeEl.textContent = info.status.charAt(0).toUpperCase() + info.status.slice(1);
      if (info.status !== "active") {
        if (cancelBtn) cancelBtn.disabled = true;
        stopCountdown();
        if (countdownEl && info.status !== "expired") countdownEl.textContent = "—";
      }
    }
  }

  /* Poll for downloads happening on someone else's device. Backs off while the
     tab is hidden so a forgotten tab is not a source of traffic. */
  var POLL_MS = 5000;
  function poll() {
    if (document.hidden) return;
    fetch(cfg.statusUrl, {
      headers: { Accept: "application/json" },
      credentials: "same-origin",
    })
      .then(function (response) {
        return response.ok ? response.json() : null;
      })
      .then(function (payload) {
        if (payload && payload.ok) render(payload);
      })
      .catch(function () {
        /* transient network failure: the next tick will retry */
      });
  }
  window.setInterval(poll, POLL_MS);
  document.addEventListener("visibilitychange", function () {
    if (!document.hidden) poll();
  });

  // ---------------------------------------------------------------- cancel --
  if (cancelBtn) {
    cancelBtn.addEventListener("click", function () {
      var sure = window.confirm(
        "Cancel this share?\n\nThe link will stop working immediately and the " +
          "encrypted file will be deleted. This cannot be undone."
      );
      if (!sure) return;

      cancelBtn.disabled = true;
      fetch(cfg.cancelUrl, {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": cfg.csrfToken,
          Accept: "application/json",
        },
        body: JSON.stringify({ key: cfg.ownerKey }),
      })
        .then(function (response) {
          return response.json().catch(function () { return {}; });
        })
        .then(function (payload) {
          if (payload && payload.ok) {
            Q.toast("Share cancelled and file deleted");
            render({ status: "deleted" });
          } else {
            Q.toast("Could not cancel the share");
            cancelBtn.disabled = false;
          }
        })
        .catch(function () {
          Q.toast("Network error");
          cancelBtn.disabled = false;
        });
    });
  }
})();
