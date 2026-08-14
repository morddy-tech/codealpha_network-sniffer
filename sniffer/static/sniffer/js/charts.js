/* Chart.js helpers.
 *
 * Chart data is embedded in the page via Django's json_script tag and read
 * with JSON.parse - never interpolated into the page. If the local Chart.js
 * file failed to load, the page still works (charts are skipped silently).
 */
(function () {
  "use strict";

  var PALETTE = [
    "#38bdf8", "#a78bfa", "#34d399", "#fbbf24", "#f87171",
    "#22d3ee", "#fb923c", "#f472b6", "#4ade80", "#93c5fd",
  ];

  function theme(overrides) {
    return Object.assign(
      {
        color: "#8fa3c0",
        borderColor: "rgba(30,48,80,0.8)",
        grid: { color: "rgba(30,48,80,0.35)" },
        ticks: { color: "#8fa3c0" },
      },
      overrides || {}
    );
  }

  // Resolves a chart target to a <canvas>. Some templates give the wrapper
  // <div> the chart id (e.g. <div id="chart-x"><canvas></canvas></div>),
  // others give the <canvas> itself; both must work.
  function canvasFor(elementId) {
    var el = document.getElementById(elementId);
    if (!el) return null;
    return el.tagName === "CANVAS" ? el : el.querySelector("canvas");
  }

  window.SnifferCharts = {
    palette: PALETTE,

    pie: function (elementId, labels, values, label) {
      if (!window.Chart || !elementId) return;
      var el = canvasFor(elementId);
      if (!el) return;
      new Chart(el.getContext("2d"), {
        type: "doughnut",
        data: {
          labels: labels,
          datasets: [{
            data: values,
            backgroundColor: PALETTE,
            borderColor: "#101c31",
            borderWidth: 2,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: "bottom",
              labels: { color: "#8fa3c0", boxWidth: 12, font: { size: 11 } },
            },
          },
        },
      });
    },

    bar: function (elementId, labels, values, label, horizontal) {
      if (!window.Chart || !elementId) return;
      var el = canvasFor(elementId);
      if (!el) return;
      new Chart(el.getContext("2d"), {
        type: "bar",
        data: {
          labels: labels,
          datasets: [{
            label: label,
            data: values,
            backgroundColor: PALETTE,
            borderColor: PALETTE,
            borderWidth: 1,
            borderRadius: 3,
          }],
        },
        options: {
          indexAxis: horizontal ? "y" : "x",
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false },
          },
          scales: {
            x: horizontal ? theme({}) : theme(),
            y: horizontal ? theme() : theme(),
          },
        },
      });
    },

    line: function (elementId, labels, values, label, fillColor) {
      if (!window.Chart || !elementId) return;
      var el = canvasFor(elementId);
      if (!el) return;
      new Chart(el.getContext("2d"), {
        type: "line",
        data: {
          labels: labels,
          datasets: [{
            label: label,
            data: values,
            borderColor: fillColor || "#38bdf8",
            backgroundColor: (fillColor || "#38bdf8") + "22",
            fill: true,
            tension: 0.3,
            pointRadius: 1.5,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: { x: theme(), y: theme() },
        },
      });
    },

    // Reads a json_script block and charts it.
    fromJsonScript: function (scriptId, builder) {
      var el = document.getElementById(scriptId);
      if (!el) return;
      var data;
      try {
        data = JSON.parse(el.textContent);
      } catch (e) {
        return;
      }
      builder(data);
    },
  };
})();
