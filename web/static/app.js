// Client-side interactions for AI-Driven Adaptive Post-Quantum Cybersecurity Logging System

let recentEvents = [];

document.addEventListener("DOMContentLoaded", () => {
  setupTabs();
  fetchSystemStatus();
  loadBlockchainData();
  loadCryptoBenchmark();

  // Periodic polling for status updates every 6 seconds
  setInterval(fetchSystemStatus, 6000);
});

// Tab Navigation
function setupTabs() {
  const tabBtns = document.querySelectorAll(".tab-btn");
  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));

      btn.classList.add("active");
      const targetId = btn.getAttribute("data-tab");
      document.getElementById(targetId).classList.add("active");

      if (targetId === "blockchain-panel") {
        loadBlockchainData();
      } else if (targetId === "benchmarks-panel") {
        loadCryptoBenchmark();
      }
    });
  });
}

// Fetch System Status & Stats
async function fetchSystemStatus() {
  try {
    const res = await fetch("/api/status");
    const data = await res.json();

    document.getElementById("stat-total-events").innerText = data.system.total_processed_events;
    document.getElementById("stat-ledger-height").innerText = data.system.blockchain_height;

    const rd = data.system.risk_distribution;
    document.getElementById("stat-risk-breakdown").innerText =
      `L: ${rd.LOW || 0} | M: ${rd.MEDIUM || 0} | H: ${rd.HIGH || 0} | C: ${rd.CRITICAL || 0}`;
  } catch (err) {
    console.error("Failed to fetch system status:", err);
  }
}

// Generate Event
async function generateEvent(tier) {
  try {
    let url = "/api/event/generate";
    if (tier) url += `?tier=${tier}`;

    const res = await fetch(url, { method: "POST" });
    const data = await res.json();

    recentEvents.unshift(data);
    if (recentEvents.length > 50) recentEvents.pop();

    renderEventsTable();
    fetchSystemStatus();
  } catch (err) {
    alert("Error generating event: " + err.message);
  }
}

// Render Ingested Events
function renderEventsTable() {
  const tbody = document.getElementById("events-tbody");
  tbody.innerHTML = "";

  recentEvents.forEach(item => {
    const rec = item.record;
    const ai = item.ai_inference;
    const tr = document.createElement("tr");

    // Risk badge class
    const rClass = `badge-${rec.risk_level.toLowerCase()}`;
    const failsafeTag = ai.failsafe_triggered ? '<span class="badge badge-high">FAILSAFE</span>' : '';

    // Algorithm display
    const isPQC = item.cryptography.is_pqc;
    const algoBadge = isPQC
      ? `<span class="badge badge-quantum">${item.cryptography.algorithm}</span>`
      : `<span class="badge badge-accent">${item.cryptography.algorithm}</span>`;

    const encTag = item.cryptography.is_payload_encrypted
      ? '<span class="badge badge-quantum" title="Encrypted with ML-KEM + AES-256-GCM">🔐 KEM Encrypted</span>'
      : '<span class="badge badge-info">Plaintext Store</span>';

    tr.innerHTML = `
      <td class="mono-cell">${rec.timestamp.split("T")[1].replace("Z", "")}</td>
      <td>
        <strong>${item.record.event_id.substring(0, 8)}...</strong><br>
        <small class="text-muted">${rec.crypto_op.split("_")[0]}</small>
      </td>
      <td>
        <span class="badge ${rClass}">${rec.risk_level}</span>
        <small class="mono-cell">(${ai.risk_score.toFixed(2)})</small>
        ${failsafeTag}
      </td>
      <td>
        ${algoBadge}<br>
        ${encTag}
      </td>
      <td class="mono-cell">
        <span title="${rec.event_hash}">H: ${rec.event_hash.substring(0, 10)}...</span><br>
        <small class="text-muted">ptr: ${rec.payload_ptr.substring(12, 32)}...</small>
      </td>
      <td>
        <button class="btn btn-sm btn-outline" onclick="openAuditModal('${rec.event_id}')">🔍 Audit Proof</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

// Forensic Audit Modal
async function openAuditModal(eventId) {
  const modal = document.getElementById("audit-modal");
  const modalBody = document.getElementById("audit-modal-body");
  modal.classList.add("active");
  modalBody.innerHTML = `<p class="text-muted">Running forensic cryptographic recomputation for event <code>${eventId}</code>...</p>`;

  try {
    const res = await fetch(`/api/event/${eventId}/audit`);
    const data = await res.json();

    const isVerified = data.audit_verdict === "VERIFIED_AUTHENTIC";
    const statusClass = isVerified ? "text-success" : "badge-crit";

    let stepsHtml = data.audit_steps.map(step => `<li>${step}</li>`).join("");

    modalBody.innerHTML = `
      <div style="margin-bottom: 1rem;">
        <h4>Status: <span class="${statusClass}"><strong>${data.audit_verdict}</strong></span></h4>
        <p class="text-muted">Verification completed in <strong>${data.audit_time_ms} ms</strong></p>
      </div>

      <div class="card" style="padding: 1rem; margin-bottom: 1rem;">
        <h5 style="margin-bottom: 0.5rem;">Audit Integrity Checklist:</h5>
        <ul style="list-style: none; padding-left: 0;">
          <li>${data.checks.ledger_inclusion ? "✅" : "❌"} <strong>DLT Block Inclusion:</strong> Validated</li>
          <li>${data.checks.merkle_inclusion ? "✅" : "❌"} <strong>Merkle Tree Inclusion Proof:</strong> Verified against block root</li>
          <li>${data.checks.offchain_payload_exists ? "✅" : "❌"} <strong>Off-Chain Payload:</strong> Located at content pointer</li>
          <li>${data.checks.hash_integrity ? "✅" : "❌"} <strong>Cryptographic Recomputation:</strong> H(stored_event) matches on-chain hash</li>
          <li>${data.checks.signature_validity ? "✅" : "❌"} <strong>Post-Quantum Signature:</strong> Non-repudiation confirmed</li>
        </ul>
      </div>

      <div class="card" style="padding: 1rem;">
        <h5 style="margin-bottom: 0.5rem;">Forensic Trace Log:</h5>
        <ul class="styled-list" style="font-size: 0.82rem;">
          ${stepsHtml}
        </ul>
      </div>
    `;
  } catch (err) {
    modalBody.innerHTML = `<p class="text-danger">Audit execution error: ${err.message}</p>`;
  }
}

function closeAuditModal() {
  document.getElementById("audit-modal").classList.remove("active");
}

// Custom Event Modal
function openCustomEventModal() {
  document.getElementById("custom-event-modal").classList.add("active");
}

function closeCustomEventModal() {
  document.getElementById("custom-event-modal").classList.remove("active");
}

async function submitCustomEvent(e) {
  e.preventDefault();
  const payload = {
    event_type: document.getElementById("cust-event-type").value,
    source_ip: document.getElementById("cust-source-ip").value,
    user_id: document.getElementById("cust-user-id").value,
    resource: document.getElementById("cust-resource").value,
    failure_count: parseInt(document.getElementById("cust-failures").value),
    is_admin_action: parseInt(document.getElementById("cust-is-admin").value),
    sensitive_target: parseInt(document.getElementById("cust-is-sensitive").value),
    action: document.getElementById("cust-action").value,
    payload: { note: "Injected via SOC Dashboard" }
  };

  try {
    const res = await fetch("/api/event/custom", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    recentEvents.unshift(data);
    renderEventsTable();
    closeCustomEventModal();
    fetchSystemStatus();
  } catch (err) {
    alert("Error submitting custom event: " + err.message);
  }
}

// Flush Mempool
async function flushLedgerPool() {
  try {
    const res = await fetch("/api/ledger/flush", { method: "POST" });
    const data = await res.json();
    if (data.block) {
      alert(`Mempool successfully committed into Block #${data.block.index}!`);
      fetchSystemStatus();
      loadBlockchainData();
    } else {
      alert("No pending transactions in mempool to commit.");
    }
  } catch (err) {
    alert("Flush error: " + err.message);
  }
}

// Attack Simulator Execution
async function runAttackTest(attackType) {
  const consoleOutput = document.getElementById("console-output");
  consoleOutput.innerText = `[${new Date().toLocaleTimeString()}] INITIATING ADVERSARIAL TEST: ${attackType.toUpperCase()}...\nContacting pipeline and dispatching attack vector...`;

  try {
    const res = await fetch(`/api/attack/simulate?attack_type=${attackType}`, { method: "POST" });
    const data = await res.json();

    consoleOutput.innerText = `[${new Date().toLocaleTimeString()}] ATTACK TEST RESULTS: ${data.test_name || attackType}\n` +
      `--------------------------------------------------------------------------------\n` +
      JSON.stringify(data, null, 2);
  } catch (err) {
    consoleOutput.innerText += `\n[ERROR] Attack simulation failed: ${err.message}`;
  }
}

function clearConsole() {
  document.getElementById("console-output").innerText = "// Console cleared. Select an attack test to execute.";
}

// Blockchain Explorer Data
async function loadBlockchainData() {
  const container = document.getElementById("blockchain-blocks-list");
  container.innerHTML = "<p class='text-muted'>Loading blockchain blocks...</p>";

  try {
    const res = await fetch("/api/ledger/blocks");
    const blocks = await res.json();

    container.innerHTML = "";
    blocks.reverse().forEach(b => {
      const card = document.createElement("div");
      card.className = "block-card";

      const valNodes = (b.validator_signatures || []).map(v => v.node_name).join(", ") || "ABESIT Consortium";

      card.innerHTML = `
        <div class="block-header">
          <h4>Block #${b.index}</h4>
          <span class="badge badge-accent">${b.records_count} Committed Records</span>
        </div>
        <div class="block-hash-line">Hash: ${b.block_hash}</div>
        <div class="block-hash-line" style="color: var(--text-muted); font-size: 0.75rem;">Prev: ${b.previous_hash}</div>
        <div class="block-hash-line" style="color: var(--quantum-teal); font-size: 0.75rem;">Merkle Root: ${b.merkle_root}</div>
        <div class="block-meta">
          <span>Timestamp: ${b.timestamp}</span>
          <span>BFT Consensus: ${valNodes}</span>
        </div>
      `;
      container.appendChild(card);
    });
  } catch (err) {
    container.innerHTML = `<p class="text-danger">Failed to load blockchain: ${err.message}</p>`;
  }
}

// Cryptographic Benchmark Table
async function loadCryptoBenchmark() {
  const tbody = document.getElementById("crypto-bench-tbody");
  tbody.innerHTML = "<tr><td colspan='7'>Running cryptographic micro-benchmarks...</td></tr>";

  try {
    const res = await fetch("/api/benchmark/crypto");
    const data = await res.json();

    tbody.innerHTML = "";
    for (const [scheme, info] of Object.entries(data)) {
      const tr = document.createElement("tr");
      const qRes = info.quantum_resistant
        ? '<span class="badge badge-quantum">QUANTUM-PROOF</span>'
        : '<span class="badge badge-crit">VULNERABLE (Shor)</span>';

      tr.innerHTML = `
        <td><strong>${scheme}</strong></td>
        <td>${info.type}</td>
        <td class="mono-cell">${info.pk_size_bytes} bytes</td>
        <td class="mono-cell">${info.sig_size_bytes} bytes</td>
        <td class="mono-cell">${info.sign_latency_ms} ms</td>
        <td class="mono-cell">${info.verify_latency_ms} ms</td>
        <td>${qRes}</td>
      `;
      tbody.appendChild(tr);
    }
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan='7' class='text-danger'>Error: ${err.message}</td></tr>`;
  }
}

// Full Comparative System Benchmark
async function runFullSystemBenchmark() {
  const container = document.getElementById("system-bench-results");
  container.innerHTML = "<p class='text-muted'>Executing 50-event comparative benchmark across B1, B2, B3, and B4... Please wait ~3-5 seconds...</p>";

  try {
    const res = await fetch("/api/benchmark/run?events_count=50", { method: "POST" });
    const data = await res.json();

    const baselines = data.baselines;
    const summary = data.summary;

    let html = `
      <div class="card" style="background: rgba(16, 185, 129, 0.08); border-color: rgba(16, 185, 129, 0.3); margin-bottom: 1.25rem;">
        <h4>🏆 Benchmark Findings (RQ4 Answered):</h4>
        <ul class="styled-list" style="margin-top: 0.5rem;">
          <li><strong>Latency Optimization:</strong> Proposed Adaptive PQC framework is <strong>${summary.latency_speedup_vs_static_pqc}x faster</strong> than static uniform PQC.</li>
          <li><strong>Storage Scalability:</strong> Saves <strong>${summary.pqc_onchain_storage_saving_percent}% on-chain ledger storage</strong> compared to static uniform PQC logging (B3).</li>
          <li><strong>Quantum Resilience:</strong> Maintains 100% post-quantum lattice security for all critical and high-value incident forensics.</li>
        </ul>
      </div>

      <div class="table-container">
        <table class="data-table">
          <thead>
            <tr>
              <th>Baseline</th>
              <th>PQC Hardness</th>
              <th>Mean Latency</th>
              <th>Median (P50)</th>
              <th>95th Percentile</th>
              <th>Throughput</th>
              <th>On-Chain Bytes/Event</th>
            </tr>
          </thead>
          <tbody>
    `;

    for (const [key, b] of Object.entries(baselines)) {
      const qBadge = b.quantum_resistant
        ? '<span class="badge badge-quantum">PQC</span>'
        : '<span class="badge badge-info">Classical</span>';

      html += `
        <tr>
          <td><strong>${b.name}</strong></td>
          <td>${qBadge}</td>
          <td class="mono-cell">${b.latency_ms.mean} ms</td>
          <td class="mono-cell">${b.latency_ms.median} ms</td>
          <td class="mono-cell">${b.latency_ms.p95} ms</td>
          <td class="mono-cell text-accent">${b.throughput_events_per_sec} ev/s</td>
          <td class="mono-cell">${b.storage_bytes.onchain_per_event} B</td>
        </tr>
      `;
    }

    html += `
          </tbody>
        </table>
      </div>
    `;

    container.innerHTML = html;
  } catch (err) {
    container.innerHTML = `<p class="text-danger">Benchmark error: ${err.message}</p>`;
  }
}
