/* Receiver page: countdown, password unlock, and starting the download. */
(function () {
  "use strict";

  var Q = window.QRShare;
  var cfg = Q.readConfig("download-config");

  Q.startCountdown(document.getElementById("countdown"), cfg.expiresAt, function () {
    // The link is dead now; reload so the server renders the expired state
    // rather than leaving a stale "Download" button on screen.
    window.location.reload();
  });

  if (cfg.status !== "active") return;

  var errorShown = false;
  function fail(message) {
    errorShown = true;
    Q.setError("download-error", "download-error-text", message);
  }
  function clearFail() {
    if (errorShown) Q.setError("download-error", "download-error-text", null);
    errorShown = false;
  }

  function busy(button, labelEl, text) {
    button.disabled = true;
    button.dataset.originalLabel = button.dataset.originalLabel || labelEl.textContent;
    labelEl.textContent = text;
  }
  function idle(button, labelEl) {
    button.disabled = false;
    labelEl.textContent = button.dataset.originalLabel || labelEl.textContent;
  }

  /**
   * Hand the URL to the browser so it streams the file natively -- no buffering
   * the whole thing in memory, and the native download UI shows progress.
   * The response is Content-Disposition: attachment, so this does not navigate
   * away from the page on success.
   */
  function beginDownload(ticket) {
    var url = cfg.downloadUrl + (ticket ? "?ticket=" + encodeURIComponent(ticket) : "");
    window.location.href = url;

    if (cfg.oneTime) {
      // The link is consumed the moment the server accepts the request.
      window.setTimeout(function () {
        Q.toast("Download started. This one-time link is now used.");
      }, 900);
    }
    // Reflect the new download count / state after the server has processed it.
    window.setTimeout(refreshStatus, 2500);
  }

  function refreshStatus() {
    fetch(cfg.statusUrl, {
      headers: { Accept: "application/json" },
      credentials: "same-origin",
    })
      .then(function (response) { return response.ok ? response.json() : null; })
      .then(function (payload) {
        if (payload && payload.ok && payload.status !== "active") {
          window.location.reload();
        }
      })
      .catch(function () { /* ignore: nothing depends on this succeeding */ });
  }

  // ------------------------------------------------------- no password ----
  var downloadBtn = document.getElementById("download-btn");
  if (downloadBtn) {
    var downloadLabel = document.getElementById("download-label");
    downloadBtn.addEventListener("click", function () {
      clearFail();
      busy(downloadBtn, downloadLabel, "Starting download…");
      beginDownload(null);
      window.setTimeout(function () { idle(downloadBtn, downloadLabel); }, 3000);
    });
  }

  // ---------------------------------------------------------- password ----
  var form = document.getElementById("password-form");
  if (!form) return;

  var input = document.getElementById("password");
  var unlockBtn = document.getElementById("unlock-btn");
  var unlockLabel = document.getElementById("unlock-label");

  input.addEventListener("input", clearFail);

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    clearFail();

    if (!input.value) {
      fail("Enter the password to continue.");
      input.focus();
      return;
    }

    busy(unlockBtn, unlockLabel, "Checking…");

    fetch(cfg.verifyUrl, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": cfg.csrfToken,
        Accept: "application/json",
      },
      body: JSON.stringify({ password: input.value }),
    })
      .then(function (response) {
        return response
          .json()
          .catch(function () { return {}; })
          .then(function (payload) { return { status: response.status, body: payload }; });
      })
      .then(function (result) {
        idle(unlockBtn, unlockLabel);

        if (result.status === 200 && result.body.ok && result.body.ticket) {
          input.value = "";
          unlockLabel.textContent = "Download starting…";
          unlockBtn.disabled = true;
          beginDownload(result.body.ticket);
          return;
        }

        if (result.status === 429) {
          fail("Too many attempts. Wait a minute before trying again.");
        } else if (result.status === 410) {
          fail(result.body.error || "This link is no longer available.");
          window.setTimeout(function () { window.location.reload(); }, 1500);
        } else {
          fail(result.body.error || "Incorrect password. Please try again.");
          input.focus();
          input.select();
        }
      })
      .catch(function () {
        idle(unlockBtn, unlockLabel);
        fail("Network error. Check your connection and try again.");
      });
  });
})();
