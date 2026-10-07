/**
 * dashboard.js
 * ============
 * Initialises Chart.js charts on the dashboard page using real data
 * passed from the Flask template via window.DASHBOARD_STATS.
 */

(function () {
  "use strict";

  const STATS = window.DASHBOARD_STATS || {};

  // ---------------------------------------------------------------- //
  // Colour palette matching CSS variables
  // ---------------------------------------------------------------- //
  const COLORS = {
    SAFE:        "#22c55e",
    "LOW RISK":  "#84cc16",
    SUSPICIOUS:  "#f59e0b",
    "HIGH RISK": "#f97316",
    MALICIOUS:   "#ef4444",
    URL:         "#58a6ff",
    IPv4:        "#a78bfa",
    IPv6:        "#34d399",
    grid:        "rgba(255,255,255,0.06)",
    text:        "#8b949e",
  };

  const CHART_DEFAULTS = {
    responsive: true,
    maintainAspectRatio: true,
    plugins: {
      legend: {
        labels: { color: COLORS.text, font: { size: 11 }, boxWidth: 12 },
      },
    },
  };

  // ---------------------------------------------------------------- //
  // 1. Verdict distribution doughnut
  // ---------------------------------------------------------------- //
  function initDistributionChart() {
    const ctx = document.getElementById("chart-distribution");
    if (!ctx) return;

    const labels = ["Safe", "Low Risk", "Suspicious", "High Risk", "Malicious"];
    const values = [
      STATS.safe_count        || 0,
      STATS.low_risk_count    || 0,
      STATS.suspicious_count  || 0,
      STATS.high_risk_count   || 0,
      STATS.malicious_count   || 0,
    ];
    const total = values.reduce((a, b) => a + b, 0);

    new Chart(ctx, {
      type: "doughnut",
      data: {
        labels,
        datasets: [{
          data: values,
          backgroundColor: Object.values(COLORS).slice(0, 5),
          borderColor: "#1a2035",
          borderWidth: 2,
        }],
      },
      options: {
        ...CHART_DEFAULTS,
        cutout: "65%",
        plugins: {
          ...CHART_DEFAULTS.plugins,
          tooltip: {
            callbacks: {
              label: (ctx) => {
                const pct = total > 0 ? ((ctx.parsed / total) * 100).toFixed(1) : 0;
                return ` ${ctx.label}: ${ctx.parsed} (${pct}%)`;
              },
            },
          },
        },
      },
    });
  }

  // ---------------------------------------------------------------- //
  // 2. Scan type bar chart
  // ---------------------------------------------------------------- //
  function initTypeChart() {
    const ctx = document.getElementById("chart-types");
    if (!ctx) return;

    new Chart(ctx, {
      type: "bar",
      data: {
        labels: ["URL", "IPv4", "IPv6"],
        datasets: [{
          label: "Scans",
          data: [
            STATS.url_count  || 0,
            STATS.ipv4_count || 0,
            STATS.ipv6_count || 0,
          ],
          backgroundColor: [COLORS.URL, COLORS.IPv4, COLORS.IPv6],
          borderRadius: 5,
          borderSkipped: false,
        }],
      },
      options: {
        ...CHART_DEFAULTS,
        maintainAspectRatio: true,
        scales: {
          x: { ticks: { color: COLORS.text }, grid: { color: COLORS.grid } },
          y: {
            beginAtZero: true,
            ticks: { color: COLORS.text, precision: 0 },
            grid: { color: COLORS.grid },
          },
        },
        plugins: { ...CHART_DEFAULTS.plugins, legend: { display: false } },
      },
    });
  }

  // ---------------------------------------------------------------- //
  // 3. Scans over time line chart
  // ---------------------------------------------------------------- //
  function initTimelineChart() {
    const ctx = document.getElementById("chart-timeline");
    if (!ctx) return;

    const daily = STATS.daily_scans || [];

    // Build a complete 30-day range (fill missing days with 0)
    const days = [];
    const counts = [];
    for (let i = 29; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      const key = d.toISOString().slice(0, 10);
      days.push(key.slice(5));      // "MM-DD"
      const found = daily.find((r) => r.day === key);
      counts.push(found ? found.count : 0);
    }

    new Chart(ctx, {
      type: "line",
      data: {
        labels: days,
        datasets: [{
          label: "Scans",
          data: counts,
          borderColor: COLORS.URL,
          backgroundColor: "rgba(88,166,255,0.08)",
          fill: true,
          tension: 0.3,
          pointRadius: 3,
          pointHoverRadius: 5,
          pointBackgroundColor: COLORS.URL,
        }],
      },
      options: {
        ...CHART_DEFAULTS,
        maintainAspectRatio: false,
        scales: {
          x: {
            ticks: { color: COLORS.text, maxTicksLimit: 10 },
            grid: { color: COLORS.grid },
          },
          y: {
            beginAtZero: true,
            ticks: { color: COLORS.text, precision: 0 },
            grid: { color: COLORS.grid },
          },
        },
        plugins: { ...CHART_DEFAULTS.plugins, legend: { display: false } },
      },
    });
  }

  // ---------------------------------------------------------------- //
  // Boot
  // ---------------------------------------------------------------- //
  document.addEventListener("DOMContentLoaded", function () {
    initDistributionChart();
    initTypeChart();
    initTimelineChart();
  });

  // Expose refresh function so scanner.js can call it after a new scan
  window.refreshDashboardStats = async function () {
    try {
      const resp = await fetch("/api/stats");
      const data = await resp.json();
      if (!data.success) return;
      const s = data.stats;
      // Update stat cards
      const ids = {
        "stat-total": s.total,
        "stat-safe":  s.safe_count,
        "stat-low":   s.low_risk_count,
        "stat-susp":  s.suspicious_count,
        "stat-high":  s.high_risk_count,
        "stat-mal":   s.malicious_count,
      };
      for (const [id, val] of Object.entries(ids)) {
        const el = document.getElementById(id);
        if (el) el.textContent = val || 0;
      }
    } catch (_) {
      // Silent – stats refresh is non-critical
    }
  };
})();
