/* General UI helpers: sidebar, tabs, confirmations. */
(function () {
  "use strict";

  document.addEventListener("DOMContentLoaded", function () {
    var burger = document.getElementById("sidebar-toggle");
    var sidebar = document.getElementById("sidebar");
    var overlay = document.getElementById("sidebar-overlay");

    function closeSidebar() {
      if (sidebar) sidebar.classList.remove("open");
      if (overlay) overlay.classList.remove("open");
    }

    if (burger && sidebar) {
      burger.addEventListener("click", function () {
        sidebar.classList.toggle("open");
        if (overlay) overlay.classList.toggle("open");
      });
    }
    if (overlay) overlay.addEventListener("click", closeSidebar);

    // Tab switching
    document.querySelectorAll("[data-tab]").forEach(function (tab) {
      tab.addEventListener("click", function () {
        var name = tab.getAttribute("data-tab");
        document.querySelectorAll(".tab-panel").forEach(function (p) {
          p.classList.remove("active");
        });
        document.querySelectorAll("[data-tab]").forEach(function (t) {
          t.classList.remove("active");
        });
        var panel = document.getElementById("tab-" + name);
        if (panel) panel.classList.add("active");
        tab.classList.add("active");
      });
    });

    // Confirmation for destructive actions
    document.querySelectorAll("[data-confirm]").forEach(function (el) {
      el.addEventListener("click", function (event) {
        var message = el.getAttribute("data-confirm");
        if (!window.confirm(message)) {
          event.preventDefault();
        }
      });
    });

    // Auto-refresh timestamps on the capture page
    var timer = document.getElementById("capture-timer");
    if (timer) {
      var startIso = timer.getAttribute("data-start");
      if (startIso) {
        window.setInterval(function () {
          var start = new Date(startIso);
          var now = new Date();
          var diff = Math.max(0, Math.floor((now - start) / 1000));
          var h = String(Math.floor(diff / 3600)).padStart(2, "0");
          var m = String(Math.floor((diff % 3600) / 60)).padStart(2, "0");
          var s = String(diff % 60).padStart(2, "0");
          timer.textContent = h + ":" + m + ":" + s;
        }, 1000);
      }
    }
  });
})();
