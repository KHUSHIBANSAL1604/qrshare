/* Upload page: drag & drop, client-side pre-checks, XHR upload with progress.
   Every check here is duplicated on the server -- this exists for speed of
   feedback, not for security. */
(function () {
  "use strict";

  var Q = window.QRShare;
  var cfg = Q.readConfig("upload-config");

  var form = document.getElementById("upload-form");
  if (!form) return;

  var dropzone = document.getElementById("dropzone");
  var fileInput = document.getElementById("file-input");
  var clearBtn = document.getElementById("file-clear");
  var stateIdle = document.getElementById("state-idle");
  var stateSelected = document.getElementById("state-selected");
  var stateUploading = document.getElementById("state-uploading");
  var stateReady = document.getElementById("state-ready");
  var nameEl = document.getElementById("file-name");
  var subEl = document.getElementById("file-sub");
  var submitBtn = document.getElementById("submit-btn");
  var submitLabel = document.getElementById("submit-label");
  var progressBar = document.getElementById("progress-bar");
  var progressPct = document.getElementById("progress-pct");
  var progressStatus = document.getElementById("progress-status");
  var cancelBtn = document.getElementById("cancel-upload");

  var expirySelect = document.getElementById("expiry");
  var customField = document.getElementById("custom-expiry-field");
  var customInput = document.getElementById("expiry-custom");
  var passwordToggle = document.getElementById("password-toggle");
  var passwordFields = document.getElementById("password-fields");
  var passwordInput = document.getElementById("password");
  var confirmInput = document.getElementById("password-confirm");

  var selected = null;
  var request = null;

  // ---------------------------------------------------------------- file --
  function extensionOf(name) {
    var dot = name.lastIndexOf(".");
    return dot === -1 ? "" : name.slice(dot + 1).toLowerCase();
  }

  function preCheck(file) {
    if (!file.size) return "That file is empty, so there is nothing to share.";
    if (file.size > cfg.maxBytes) {
      return "That file is " + Q.humanSize(file.size) + ", over the " + cfg.maxMb + " MB limit.";
    }
    var ext = extensionOf(file.name);
    if (cfg.allowed && cfg.allowed.length) {
      if (cfg.allowed.indexOf(ext) === -1) return "That file type is not allowed.";
    } else if (ext && cfg.blocked && cfg.blocked.indexOf(ext) !== -1) {
      return "Executable file types cannot be shared for security reasons.";
    }
    return null;
  }

  function selectFile(file) {
    Q.setError("form-error", "form-error-text", null);
    var problem = preCheck(file);
    if (problem) {
      Q.setError("form-error", "form-error-text", problem);
      clearFile();
      return;
    }
    selected = file;
    nameEl.textContent = file.name;
    subEl.textContent = Q.humanSize(file.size) + (file.type ? " · " + file.type : "");
    Q.show(stateIdle, false);
    Q.show(stateSelected, true);
    submitBtn.disabled = false;
  }

  function clearFile() {
    selected = null;
    fileInput.value = "";
    Q.show(stateIdle, true);
    Q.show(stateSelected, false);
    submitBtn.disabled = true;
  }

  fileInput.addEventListener("change", function () {
    if (fileInput.files && fileInput.files[0]) selectFile(fileInput.files[0]);
  });
  clearBtn.addEventListener("click", clearFile);

  // ------------------------------------------------------------ drag/drop --
  ["dragenter", "dragover"].forEach(function (name) {
    dropzone.addEventListener(name, function (event) {
      event.preventDefault();
      dropzone.classList.add("is-dragging");
    });
  });
  ["dragleave", "drop"].forEach(function (name) {
    dropzone.addEventListener(name, function (event) {
      event.preventDefault();
      dropzone.classList.remove("is-dragging");
    });
  });
  dropzone.addEventListener("drop", function (event) {
    var files = event.dataTransfer && event.dataTransfer.files;
    if (files && files[0]) selectFile(files[0]);
  });
  // Dropping a file anywhere else should not navigate away from the form.
  ["dragover", "drop"].forEach(function (name) {
    window.addEventListener(name, function (event) {
      if (!dropzone.contains(event.target)) event.preventDefault();
    });
  });

  // -------------------------------------------------------------- options --
  expirySelect.addEventListener("change", function () {
    Q.show(customField, expirySelect.value === "custom");
  });

  passwordToggle.addEventListener("change", function () {
    passwordFields.classList.toggle("is-open", passwordToggle.checked);
    if (passwordToggle.checked) {
      window.setTimeout(function () { passwordInput.focus(); }, 180);
    } else {
      passwordInput.value = "";
      confirmInput.value = "";
    }
  });

  function chosenExpiry() {
    if (expirySelect.value !== "custom") return expirySelect.value;
    return customInput.value;
  }

  // ---------------------------------------------------------------- state --
  function setUploading(active) {
    Q.show(stateUploading, active);
    Q.show(stateReady, !active);
    Q.show(stateSelected, !active);
    submitBtn.disabled = active;
  }

  function setProgress(fraction, label) {
    var pct = Math.round(Math.min(1, Math.max(0, fraction)) * 100);
    // CSSOM writes are allowed by the CSP; a style="" attribute would not be.
    progressBar.style.width = pct + "%";
    progressPct.textContent = pct + "%";
    if (label) progressStatus.textContent = label;
  }

  // --------------------------------------------------------------- submit --
  form.addEventListener("submit", function (event) {
    event.preventDefault();
    Q.setError("form-error", "form-error-text", null);

    if (!selected) {
      Q.setError("form-error", "form-error-text", "Choose a file first.");
      return;
    }

    var expiry = parseInt(chosenExpiry(), 10);
    if (!expiry || expiry < 1 || expiry > cfg.maxExpiry) {
      Q.setError("form-error", "form-error-text",
        "Expiry must be between 1 and " + cfg.maxExpiry + " minutes.");
      return;
    }

    if (passwordToggle.checked) {
      if (passwordInput.value.length < 6) {
        Q.setError("form-error", "form-error-text", "Password must be at least 6 characters.");
        passwordInput.focus();
        return;
      }
      if (passwordInput.value !== confirmInput.value) {
        Q.setError("form-error", "form-error-text", "The two passwords do not match.");
        confirmInput.focus();
        return;
      }
    }

    var data = new FormData();
    data.append("file", selected);
    data.append("expiry_minutes", String(expiry));
    if (document.getElementById("onetime-toggle").checked) data.append("one_time", "true");
    if (passwordToggle.checked) {
      data.append("password_protect", "true");
      data.append("password", passwordInput.value);
      data.append("password_confirm", confirmInput.value);
    }

    // XMLHttpRequest rather than fetch(): only XHR reports upload progress.
    request = new XMLHttpRequest();
    request.open("POST", cfg.uploadUrl, true);
    request.setRequestHeader("X-CSRFToken", form.querySelector("[name=csrf_token]").value);
    request.setRequestHeader("Accept", "application/json");

    setUploading(true);
    setProgress(0, "Uploading…");

    request.upload.addEventListener("progress", function (event) {
      if (!event.lengthComputable) return;
      setProgress(event.loaded / event.total, "Uploading…");
      if (event.loaded === event.total) {
        setProgress(1, "Encrypting on the server…");
      }
    });

    request.addEventListener("load", function () {
      var payload = {};
      try {
        payload = JSON.parse(request.responseText);
      } catch (err) {
        payload = {};
      }

      if (request.status === 201 && payload.ok) {
        setProgress(1, "Done — building your QR code…");
        window.location.href = payload.manage_url;
        return;
      }

      setUploading(false);
      if (request.status === 413) {
        Q.setError("form-error", "form-error-text",
          "That file is over the " + cfg.maxMb + " MB limit.");
      } else if (request.status === 429) {
        Q.setError("form-error", "form-error-text",
          "Too many uploads from this address. Please wait a minute and try again.");
      } else {
        Q.setError("form-error", "form-error-text",
          payload.error || "Upload failed. Please try again.");
      }
    });

    request.addEventListener("error", function () {
      setUploading(false);
      Q.setError("form-error", "form-error-text",
        "Network error. Check your connection and try again.");
    });

    request.addEventListener("abort", function () {
      setUploading(false);
      Q.toast("Upload cancelled");
    });

    request.send(data);
  });

  cancelBtn.addEventListener("click", function () {
    if (request) request.abort();
  });

  // Guard against losing an in-flight upload to an accidental navigation.
  window.addEventListener("beforeunload", function (event) {
    if (request && request.readyState > 0 && request.readyState < 4) {
      event.preventDefault();
      event.returnValue = "";
    }
  });

  submitLabel.textContent = "Encrypt & create QR code";
})();
