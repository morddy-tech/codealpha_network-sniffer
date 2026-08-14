/* Live capture page: status polling and start/stop controls.
 * The web server never blocks - the capture runs in a background worker
 * thread and this script polls /capture/status/ every 2 seconds.
 */
(function () {
  "use strict";

  document.addEventListener("DOMContentLoaded", function () {
    var form = document.getElementById("capture-form");
    var startBtn = document.getElementById("capture-start");
    var stopBtn = document.getElementById("capture-stop");
    var statusPill = document.getElementById("capture-status-pill");
    var errorEl = document.getElementById("capture-error");

    var pollTimer = null;
    var runningSessionId = null;

    function setPill(status) {
      if (!statusPill) return;
      var map = {
        running: ["running", "CAPTURING"],
        stopping: ["stopping", "STOPPING"],
        completed: ["completed", "COMPLETED"],
        failed: ["failed", "FAILED"],
        idle: ["idle", "IDLE"],
      };
      var entry = map[status] || ["idle", status.toUpperCase()];
      statusPill.className = "status-pill " + entry[0];
      statusPill.textContent = entry[1];
    }

    function render(status) {
      setPill(status.status);
      document.getElementById("cap-session").textContent = status.session_id || "-";
      document.getElementById("cap-interface").textContent = status.interface || "-";
      document.getElementById("cap-packets").textContent =
        (status.packet_count || 0).toLocaleString();
      document.getElementById("cap-bytes").textContent = formatBytes(status.byte_count || 0);
      document.getElementById("cap-filter").textContent = status.protocol_filter || "all";
      var startEl = document.getElementById("cap-started");
      if (startEl && status.started_at) {
        startEl.textContent = new Date(status.started_at).toLocaleString();
      }
      if (errorEl && status.error) {
        errorEl.textContent = "Error: " + status.error;
        errorEl.style.display = "block";
      }

      var running = status.status === "running" || status.status === "stopping";
      if (running) {
        if (status.session_id) runningSessionId = status.session_id;
        startBtn.disabled = true;
        stopBtn.disabled = status.status === "stopping";
      } else {
        startBtn.disabled = false;
        stopBtn.disabled = true;
      }
      if (form) form.style.display = running ? "none" : "block";
    }

    function poll() {
      fetch(window.SNIFFER_CSRF ? "/capture/status/" : "/capture/status/", {
        credentials: "same-origin",
        headers: { "X-Requested-With": "XMLHttpRequest" },
      })
        .then(function (r) { return r.json(); })
        .then(render)
        .catch(function () { /* keep polling */ });
    }

    function csrf() {
      // The CSRF token is present in the form's hidden input; with
      // CSRF_COOKIE_HTTPONLY the cookie itself is not readable by JS.
      if (form) {
        var input = form.querySelector('input[name="csrfmiddlewaretoken"]');
        if (input && input.value) return input.value;
      }
      var cookie = document.cookie.match(/csrftoken=([\w-]+)/);
      return cookie ? cookie[1] : "";
    }

    if (startBtn) {
      startBtn.addEventListener("click", function () {
        if (!form) return;
        var data = new FormData(form);
        startBtn.disabled = true;
        startBtn.textContent = "Starting…";
        fetch("/capture/start/", {
          method: "POST",
          credentials: "same-origin",
          headers: { "X-CSRFToken": csrf() },
          body: data,
        })
          .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
          .then(function (res) {
            if (res.ok && res.j.ok) {
              runningSessionId = res.j.session_id;
              if (errorEl) errorEl.style.display = "none";
            } else {
              if (errorEl) {
                errorEl.textContent = "Error: " + (res.j.error || "unknown error");
                errorEl.style.display = "block";
              }
            }
            startBtn.disabled = false;
            startBtn.textContent = "Start Capture";
            poll();
          });
      });
    }

    if (stopBtn) {
      stopBtn.addEventListener("click", function () {
        if (!runningSessionId) return;
        stopBtn.disabled = true;
        var data = new FormData();
        data.append("session_id", String(runningSessionId));
        fetch("/capture/stop/", {
          method: "POST",
          credentials: "same-origin",
          headers: { "X-CSRFToken": csrf() },
          body: data,
        })
          .then(function (r) { return r.json(); })
          .then(function () {
            window.setTimeout(poll, 1500);
          });
      });
    }

    function formatBytes(size) {
      var units = ["B", "KB", "MB", "GB", "TB"];
      var value = Number(size) || 0;
      var i = 0;
      while (value >= 1024 && i < units.length - 1) {
        value /= 1024;
        i += 1;
      }
      return value.toFixed(i === 0 ? 0 : 1) + " " + units[i];
    }

    poll();
    pollTimer = window.setInterval(poll, 2000);
  });
})();
