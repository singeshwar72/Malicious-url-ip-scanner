/**
 * scanner.js
 * ==========
 * Handles the scan form: validation, AJAX submission, loading state,
 * inline result display, and recent-scans table update.
 */

(function () {
  "use strict";

  // ---------------------------------------------------------------- //
  // DOM refs
  // ---------------------------------------------------------------- //
  const form        = document.getElementById("scan-form");
  const input       = document.getElementById("scan-input");
  const scanBtn     = document.getElementById("scan-btn");
  const clearBtn    = document.getElementById("clear-btn");
  const loading     = document.getElementById("scan-loading");
  const resultBox   = document.getElementById("scan-result-inline");
  const inputError  = document.getElementById("input-error");
  const recentTbody = document.getElementById("recent-tbody");

  if (!form) return;   // Not on a page with the scan form

  // ---------------------------------------------------------------- //
  // Demo target buttons
  // ---------------------------------------------------------------- //
  document.querySelectorAll(".demo-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      input.value = btn.dataset.target;
      input.focus();
    });
  });

  // ---------------------------------------------------------------- //
  // Clear button
  // ---------------------------------------------------------------- //
  clearBtn?.addEventListener("click", () => {
    input.value = "";
    clearError();
    hideResult();
    input.focus();
  });

  // ---------------------------------------------------------------- //
  // Form submit
  // ---------------------------------------------------------------- //
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const target = input.value.trim();

    // Client-side pre-validation
    if (!target) {
      showError("Please enter a URL or IP address.");
      return;
    }
    if (target.length > 2048) {
      showError("Input is too long (max 2048 characters).");
      return;
    }

    clearError();
    showLoading(true);
    hideResult();

    try {
      const resp = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target }),
      });

      const data = await resp.json();

      if (!resp.ok || !data.success) {
        showError(data.error || "Scan failed. Please check your input.");
        return;
      }

      // Show inline result summary
      showInlineResult(data);

      // Refresh stat cards / charts
      if (typeof window.refreshDashboardStats === "function") {
        window.refreshDashboardStats();
      }

      // Prepend to recent-scans table if present
      if (recentTbody) {
        prependRecentRow(data);
      }

    } catch (err) {
      console.error("Scan error:", err);
      showError("Network error. Please check your connection and try again.");
    } finally {
      showLoading(false);
    }
  });

  // ---------------------------------------------------------------- //
  // UI helpers
  // ---------------------------------------------------------------- //

  function showLoading(visible) {
    loading?.classList.toggle("d-none", !visible);
    if (scanBtn) scanBtn.disabled = visible;
  }

  function showError(msg) {
    if (!inputError) return;
    inputError.textContent = msg;
    inputError.style.display = "block";
    input?.classList.add("is-invalid");
  }

  function clearError() {
    if (inputError) { inputError.textContent = ""; inputError.style.display = "none"; }
    input?.classList.remove("is-invalid");
  }

  function hideResult() {
    if (resultBox) {
      resultBox.innerHTML = "";
      resultBox.classList.add("d-none");
    }
  }

  function showInlineResult(data) {
    if (!resultBox) return;

    const verdictClass = data.verdict.toLowerCase().replace(/ /g, "-");
    const scoreColor   = verdictColorHex(data.verdict);
    const icon         = verdictIcon(data.verdict);
    const reasonsHtml  = (data.reasons || []).slice(0, 5).map(
      (r) => `<li class="small text-warning font-mono">${escHtml(r)}</li>`
    ).join("");

    resultBox.innerHTML = `
      <div class="result-card ${verdictClass}">
        <div class="d-flex justify-content-between align-items-start flex-wrap gap-2 mb-2">
          <div>
            <div class="small text-muted mb-1">SCAN COMPLETE</div>
            <div class="font-mono fw-bold text-break" style="font-size:.9rem">${escHtml(data.target)}</div>
            <div class="mt-1"><span class="badge bg-secondary me-1">${escHtml(data.type)}</span></div>
          </div>
          <div class="text-end">
            <div class="verdict-badge verdict-${verdictClass} mb-1">${escHtml(data.verdict)}</div>
            <div style="color:${scoreColor};font-size:1.6rem;font-weight:800;line-height:1">
              ${data.risk_score}<span style="font-size:.9rem;color:#8b949e"> /100</span>
            </div>
          </div>
        </div>
        ${reasonsHtml ? `<ul class="mt-2 mb-1 ps-3">${reasonsHtml}</ul>` : '<p class="small text-success mb-1"><i class="bi bi-check-circle me-1"></i>No suspicious indicators.</p>'}
        <div class="mt-2 pt-2 border-top" style="border-color:rgba(255,255,255,.1)!important">
          <a href="/result/${data.scan_id}" class="btn btn-sm btn-outline-light me-1">
            <i class="bi bi-file-text me-1"></i>Full Report
          </a>
          <span class="small text-muted">${data.recommendation}</span>
        </div>
      </div>`;
    resultBox.classList.remove("d-none");
  }

  function prependRecentRow(data) {
    const verdictClass = data.verdict.toLowerCase().replace(/ /g, "-");
    const now = new Date().toISOString().slice(0, 19).replace("T", " ");
    const row = document.createElement("tr");
    row.innerHTML = `
      <td class="font-mono text-truncate" style="max-width:240px" title="${escHtml(data.target)}">${escHtml(data.target)}</td>
      <td><span class="badge bg-secondary">${escHtml(data.type)}</span></td>
      <td>
        <div class="d-flex align-items-center gap-2">
          <div class="risk-bar-wrap">
            <div class="risk-bar risk-bar--${verdictClass}" style="width:${data.risk_score}%"></div>
          </div>
          <span class="small">${data.risk_score}</span>
        </div>
      </td>
      <td><span class="verdict-badge verdict-${verdictClass}">${escHtml(data.verdict)}</span></td>
      <td class="text-muted small">${now}</td>
      <td>
        <a href="/result/${data.scan_id}" class="btn btn-sm btn-outline-info">
          <i class="bi bi-eye"></i>
        </a>
      </td>`;

    // Remove "no scans" placeholder row if present
    const placeholder = recentTbody.querySelector("td[colspan]");
    if (placeholder) placeholder.closest("tr").remove();

    recentTbody.insertBefore(row, recentTbody.firstChild);

    // Keep max 10 rows
    while (recentTbody.children.length > 10) {
      recentTbody.removeChild(recentTbody.lastChild);
    }
  }

  // ---------------------------------------------------------------- //
  // Utility
  // ---------------------------------------------------------------- //

  function escHtml(str) {
    const div = document.createElement("div");
    div.textContent = String(str);
    return div.innerHTML;
  }

  function verdictColorHex(v) {
    const m = {
      "SAFE": "#22c55e", "LOW RISK": "#84cc16",
      "SUSPICIOUS": "#f59e0b", "HIGH RISK": "#f97316", "MALICIOUS": "#ef4444",
    };
    return m[v] || "#8b949e";
  }

  function verdictIcon(v) {
    const m = {
      "SAFE": "check-circle", "LOW RISK": "info-circle",
      "SUSPICIOUS": "exclamation-triangle", "HIGH RISK": "exclamation-octagon", "MALICIOUS": "x-octagon",
    };
    return m[v] || "question-circle";
  }

})();
