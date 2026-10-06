const state = {
  groups: [],
  endpoints: [],
  settings: { baseUrl: "https://omnidim.io/api/v1", hasApiKey: false },
  activeGroup: "Sessions",
  selectedEndpointId: null,
  history: [],
  historyPage: 1,
  historyLimit: 25,
  historySearch: "",
  historyTotal: 0,
  historyTotalPages: 1,
  savedPayloads: [],
  view: "endpoints",
  lastResponse: null,
  csrfToken: "",
  localToken: ""
};

const refs = {};

document.addEventListener("DOMContentLoaded", init);

async function init() {
  cacheRefs();
  bindStaticEvents();
  await loadSession();
  await Promise.all([loadCatalog(), loadSettings(), loadHistory(), loadSavedPayloads()]);
  state.selectedEndpointId = state.endpoints[0]?.id || null;
  render();
}

async function loadSession() {
  // 1. Check URL fragment for one-time token handover
  const hash = window.location.hash || "";
  if (hash.includes("token=")) {
    const match = hash.match(/token=([^&]+)/);
    if (match) {
      state.localToken = decodeURIComponent(match[1]);
      history.replaceState(null, "", window.location.pathname + window.location.search);
    }
  }

  // 2. Check meta tags
  if (!state.localToken) {
    const metaLocal = document.querySelector('meta[name="local-token"]')?.getAttribute("content");
    if (metaLocal) {
      state.localToken = metaLocal;
    }
  }

  const metaCsrf = document.querySelector('meta[name="csrf-token"]')?.getAttribute("content");
  if (metaCsrf) {
    state.csrfToken = metaCsrf;
  }

  // 3. Fallback to /api/session if needed
  if (!state.csrfToken || !state.localToken) {
    try {
      const data = await api("/api/session");
      if (data) {
        if (data.csrfToken) state.csrfToken = data.csrfToken;
        if (data.localToken && !state.localToken) state.localToken = data.localToken;
      }
    } catch (err) {
      console.warn("Could not load session metadata:", err);
    }
  }
}

function cacheRefs() {
  [
    "groupNav",
    "endpointList",
    "endpointDetail",
    "groupTitle",
    "groupDescription",
    "searchInput",
    "baseUrlInput",
    "apiKeyInput",
    "saveSettingsBtn",
    "clearKeyBtn",
    "connectionDot",
    "connectionLabel",
    "connectionDetail",
    "totalEndpointCount",
    "currentGroupStat",
    "savedPayloadCount",
    "lastResponseStat",
    "endpointView",
    "historyView",
    "databaseView",
    "historyRows",
    "historySearchInput",
    "historyPrevBtn",
    "historyNextBtn",
    "historyPageInfo",
    "savedPayloadList",
    "clearHistoryBtn",
    "readOnlyBadge",
    "toast"
  ].forEach((id) => {
    refs[id] = document.getElementById(id);
  });
}

function bindStaticEvents() {
  refs.searchInput.addEventListener("input", renderEndpointList);
  refs.saveSettingsBtn.addEventListener("click", saveSettings);
  refs.clearKeyBtn.addEventListener("click", clearApiKey);
  refs.clearHistoryBtn.addEventListener("click", clearHistory);
  refs.historySearchInput?.addEventListener("input", (e) => {
    state.historySearch = e.target.value.trim();
    loadHistory(1);
  });
  refs.historyPrevBtn?.addEventListener("click", () => {
    if (state.historyPage > 1) {
      loadHistory(state.historyPage - 1);
    }
  });
  refs.historyNextBtn?.addEventListener("click", () => {
    if (state.historyPage < state.historyTotalPages) {
      loadHistory(state.historyPage + 1);
    }
  });
  document.querySelectorAll("[data-view]").forEach((button) => {
    button.addEventListener("click", () => setView(button.dataset.view));
  });
}

async function api(path, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {})
  };
  if (state.localToken) {
    headers["X-Local-Token"] = state.localToken;
  }
  if (["POST", "PUT", "PATCH", "DELETE"].includes(method) && state.csrfToken) {
    headers["X-CSRF-Token"] = state.csrfToken;
  }
  const response = await fetch(path, {
    ...options,
    headers
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || data.detail || `Request failed with ${response.status}`);
  }
  return data;
}

async function loadCatalog() {
  const data = await api("/api/endpoints");
  state.groups = data.groups;
  state.endpoints = data.endpoints;
}

async function loadSettings() {
  state.settings = await api("/api/settings");
  refs.baseUrlInput.value = state.settings.baseUrl;
  refs.apiKeyInput.value = "";
  refs.apiKeyInput.placeholder = state.settings.hasApiKey
    ? `Saved ${state.settings.apiKeyPreview}`
    : "Paste key to save";
  if (refs.readOnlyBadge) {
    refs.readOnlyBadge.hidden = !state.settings.readOnly;
  }
}


async function loadHistory(page = 1) {
  state.historyPage = page;
  const q = new URLSearchParams({
    page: String(state.historyPage),
    limit: String(state.historyLimit || 25),
  });
  if (state.historySearch) {
    q.set("search", state.historySearch);
  }
  try {
    const data = await api(`/api/history?${q.toString()}`);
    state.history = data.items || data.records || [];
    state.historyTotal = data.total ?? state.history.length;
    state.historyTotalPages = data.totalPages || 1;
  } catch (error) {
    state.history = [];
    state.historyTotal = 0;
    state.historyTotalPages = 1;
  }
  renderHistory();
}

async function loadSavedPayloads() {
  const data = await api("/api/saved-payloads");
  state.savedPayloads = data.records || [];
}

function render() {
  renderSettingsState();
  renderGroupNav();
  renderSummary();
  renderEndpointList();
  renderRunner();
  renderHistory();
  renderSavedPayloads();
  setView(state.view);
}

function renderSettingsState() {
  refs.connectionDot.classList.toggle("ready", state.settings.hasApiKey);
  refs.connectionDot.classList.toggle("missing", !state.settings.hasApiKey);
  const src = state.settings.apiKeySource ? ` (${state.settings.apiKeySource.toUpperCase()})` : "";
  refs.connectionLabel.textContent = state.settings.hasApiKey ? `API key ready${src}` : "API key needed";
  refs.connectionDetail.textContent = state.settings.securityNotice || (state.settings.hasApiKey
    ? "Requests will use the private backend"
    : "Save a key before sending");
}

function renderGroupNav() {
  refs.groupNav.innerHTML = state.groups
    .map((group) => {
      const count = group.endpoints.length;
      const active = group.name === state.activeGroup ? "active" : "";
      return `
        <button class="group-button ${active}" type="button" data-group="${escapeHtml(group.name)}">
          <strong>${escapeHtml(group.name)}</strong>
          <span>${count}</span>
        </button>
      `;
    })
    .join("");

  refs.groupNav.querySelectorAll("[data-group]").forEach((button) => {
    button.addEventListener("click", () => {
      state.activeGroup = button.dataset.group;
      state.view = "endpoints";
      const first = state.endpoints.find((endpoint) => endpoint.group === state.activeGroup);
      state.selectedEndpointId = first?.id || state.selectedEndpointId;
      render();
    });
  });
}

function renderSummary() {
  refs.totalEndpointCount.textContent = state.endpoints.length;
  refs.currentGroupStat.textContent = state.activeGroup;
  refs.savedPayloadCount.textContent = state.savedPayloads.length;
  refs.lastResponseStat.textContent = state.lastResponse
    ? `${state.lastResponse.status || "network"} in ${state.lastResponse.durationMs || 0} ms`
    : "None";
}

function renderEndpointList() {
  const search = refs.searchInput.value.trim().toLowerCase();
  const currentGroup = state.groups.find((group) => group.name === state.activeGroup);
  const scoped = search
    ? state.endpoints
    : state.endpoints.filter((endpoint) => endpoint.group === state.activeGroup);
  const filtered = scoped.filter((endpoint) => {
    const haystack = `${endpoint.group} ${endpoint.method} ${endpoint.path} ${endpoint.summary}`.toLowerCase();
    return haystack.includes(search);
  });

  refs.groupTitle.textContent = search ? "Search results" : state.activeGroup;
  refs.groupDescription.textContent = search
    ? `${filtered.length} matching endpoint${filtered.length === 1 ? "" : "s"}`
    : currentGroup?.description || "";

  refs.endpointList.innerHTML = filtered.length
    ? filtered.map(endpointButtonHtml).join("")
    : `<div class="empty-state"><h3>No endpoints found</h3><p>Try a method, path, or section name.</p></div>`;

  refs.endpointList.querySelectorAll("[data-endpoint-id]").forEach((button) => {
    button.addEventListener("click", () => {
      state.selectedEndpointId = button.dataset.endpointId;
      const endpoint = findEndpoint(state.selectedEndpointId);
      if (endpoint) {
        state.activeGroup = endpoint.group;
      }
      state.view = "endpoints";
      render();
    });
  });
}

function endpointButtonHtml(endpoint) {
  const active = endpoint.id === state.selectedEndpointId ? "active" : "";
  const danger = endpoint.danger ? `<span class="endpoint-note">Protected action</span>` : "";
  return `
    <button class="endpoint-item ${active}" type="button" data-endpoint-id="${escapeHtml(endpoint.id)}">
      <span class="method ${endpoint.method.toLowerCase()}">${endpoint.method}</span>
      <span>
        <span class="endpoint-title">${escapeHtml(endpoint.summary)}</span>
        <span class="endpoint-path">${escapeHtml(endpoint.path)}</span>
        ${danger}
      </span>
    </button>
  `;
}

function renderRunner() {
  const endpoint = findEndpoint(state.selectedEndpointId);
  if (!endpoint) {
    refs.endpointDetail.className = "empty-state";
    refs.endpointDetail.innerHTML = `<h2>Select an endpoint</h2><p>Choose the next action from the sequence to build and send a request.</p>`;
    return;
  }

  const queryText = pretty(endpoint.queryExample || {});
  const showBody = ["POST", "PUT", "PATCH", "DELETE"].includes(endpoint.method);
  const bodyText = pretty(endpoint.bodyExample ?? {});
  const pathFields = endpoint.pathParams
    .map(
      (param) => `
        <label>
          <span>${escapeHtml(param)}</span>
          <input class="path-param" data-param="${escapeHtml(param)}" type="text" placeholder="${escapeHtml(param)}">
        </label>
      `
    )
    .join("");

  refs.endpointDetail.className = "runner-inner";
  refs.endpointDetail.innerHTML = `
    <div class="runner-header">
      <div class="runner-title-row">
        <span class="method ${endpoint.method.toLowerCase()}">${endpoint.method}</span>
        <h2>${escapeHtml(endpoint.summary)}</h2>
      </div>
      <p>${escapeHtml(endpoint.group)} endpoint. Base URL stays on the server and your key is never exposed to this page.</p>
    </div>

    <div class="form-area">
      ${endpoint.note ? `<p class="meta-line">${escapeHtml(endpoint.note)}</p>` : ""}
      <label>
        <span>Request path</span>
        <input id="resolvedPathInput" type="text" value="${escapeHtml(endpoint.path)}" autocomplete="off">
      </label>

      ${pathFields ? `<div class="field-grid">${pathFields}</div>` : ""}

      ${endpoint.path === "/knowledge_base/create" ? fileHelperHtml() : ""}

      <div class="textarea-grid">
        <label class="text-panel">
          <span>Query JSON</span>
          <textarea id="queryJson" spellcheck="false">${escapeHtml(queryText)}</textarea>
        </label>
        <label class="text-panel ${showBody ? "" : "hidden"}">
          <span>Body JSON</span>
          <textarea id="bodyJson" spellcheck="false">${escapeHtml(bodyText)}</textarea>
        </label>
      </div>

      ${endpoint.danger ? dangerBoxHtml(endpoint) : ""}

      <div class="inline-actions">
        <button id="sendRequestBtn" class="button primary" type="button">Send request</button>
        <button id="savePayloadBtn" class="button" type="button">Save payload</button>
        <button id="copyCurlBtn" class="button" type="button">Copy cURL</button>
        <button id="resetFormBtn" class="button subtle" type="button">Reset</button>
      </div>
    </div>

    <div class="response-panel">
      <div class="response-head">
        <strong>Response</strong>
        <span id="responseMeta" class="response-meta">Waiting for request</span>
      </div>
      <pre id="responseOutput">{}</pre>
    </div>
  `;

  bindRunnerEvents(endpoint);
}

function fileHelperHtml() {
  return `
    <div class="file-helper">
      <label>
        <span>PDF helper</span>
        <input id="knowledgeFileInput" type="file" accept="application/pdf">
      </label>
      <button id="loadPdfBtn" class="button" type="button">Add to body</button>
    </div>
  `;
}

function dangerBoxHtml(endpoint) {
  return `
    <label class="danger-box">
      <input id="confirmDangerInput" type="checkbox">
      <span>
        <strong>Confirm protected action</strong><br>
        This endpoint may create cost, place calls, delete data, change credits, or alter live campaigns.
      </span>
    </label>
  `;
}

function bindRunnerEvents(endpoint) {
  document.getElementById("sendRequestBtn").addEventListener("click", () => runEndpoint(endpoint));
  document.getElementById("savePayloadBtn").addEventListener("click", () => savePayload(endpoint));
  document.getElementById("copyCurlBtn").addEventListener("click", () => copyCurl(endpoint));
  document.getElementById("resetFormBtn").addEventListener("click", renderRunner);

  document.querySelectorAll(".path-param").forEach((input) => {
    input.addEventListener("input", () => updateResolvedPath(endpoint));
  });

  const loadPdfBtn = document.getElementById("loadPdfBtn");
  if (loadPdfBtn) {
    loadPdfBtn.addEventListener("click", addPdfToBody);
  }
}

function updateResolvedPath(endpoint) {
  let path = endpoint.path;
  let hasError = false;
  document.querySelectorAll(".path-param").forEach((input) => {
    const value = input.value.trim();
    if (value) {
      if (/[/?#]|[\x00-\x1f\x7f]|\.\./.test(value)) {
        hasError = true;
        showToast(`Parameter '${input.dataset.param}' contains invalid characters.`);
        return;
      }
      path = path.replace(`{${input.dataset.param}}`, encodeURIComponent(value));
    }
  });
  if (!hasError) {
    document.getElementById("resolvedPathInput").value = path;
  }
}

function getEstimatedImpact(endpoint, path) {
  const p = path.toLowerCase();
  const m = endpoint.method.toUpperCase();
  if (p.includes("/calls/dispatch") || p.includes("/bulk_call/create") || p.includes("/start")) {
    return "⚠️ Telephony / Calling Impact: This will place or launch real outbound voice calls. These calls consume telephony minutes and account balance.";
  }
  if (p.includes("credits") || p.includes("transfer") || p.includes("revert")) {
    return "⚠️ Financial / Credit Impact: This action will deduct, transfer, or modify real organization credits immediately.";
  }
  if (m === "DELETE" || p.includes("delete") || p.includes("release")) {
    return "⚠️ Destructive Action: This action permanently deletes or releases the selected resource from OmniDimension.";
  }
  if (p.includes("/import/")) {
    return "⚠️ Telephony Configuration: This imports external carrier or SIP trunk credentials into the system.";
  }
  return "⚠️ Protected Action: This endpoint modifies live production resources or account access.";
}

function promptDangerousConfirmation(endpoint, payload) {
  return new Promise((resolve) => {
    const dialog = document.getElementById("dangerDialog");
    if (!dialog || typeof dialog.showModal !== "function") {
      const ok = window.confirm(`Confirm dangerous action '${endpoint.summary}'?\n\nURL: ${buildFullUrl(state.settings.baseUrl, payload.path, payload.query)}`);
      resolve(ok ? endpoint.summary : null);
      return;
    }

    const title = document.getElementById("modalActionTitle");
    const impact = document.getElementById("modalImpactText");
    const method = document.getElementById("modalMethod");
    const urlEl = document.getElementById("modalUrl");
    const preview = document.getElementById("modalBodyPreview");
    const promptText = document.getElementById("modalPromptText");
    const input = document.getElementById("modalConfirmInput");
    const confirmBtn = document.getElementById("modalConfirmBtn");
    const cancelBtn = document.getElementById("modalCancelBtn");

    title.textContent = `Confirm: ${endpoint.summary}`;
    impact.textContent = getEstimatedImpact(endpoint, payload.path);
    method.textContent = endpoint.method;
    urlEl.textContent = buildFullUrl(state.settings.baseUrl, payload.path, payload.query);
    preview.textContent = payload.body ? pretty(payload.body) : "(No request body)";
    promptText.textContent = `Type "${endpoint.summary}" to confirm:`;
    input.value = "";
    confirmBtn.disabled = true;

    function onInput() {
      confirmBtn.disabled = input.value.trim() !== endpoint.summary.trim();
    }
    input.addEventListener("input", onInput);

    function cleanup() {
      input.removeEventListener("input", onInput);
      confirmBtn.onclick = null;
      cancelBtn.onclick = null;
      dialog.close();
    }

    confirmBtn.onclick = () => {
      cleanup();
      resolve(endpoint.summary);
    };

    cancelBtn.onclick = () => {
      cleanup();
      resolve(null);
    };

    dialog.showModal();
  });
}

async function addPdfToBody() {
  const input = document.getElementById("knowledgeFileInput");
  const file = input.files[0];
  if (!file) {
    showToast("Choose a PDF first.");
    return;
  }
  const base64 = await readFileAsBase64(file);
  const bodyArea = document.getElementById("bodyJson");
  const body = parseJson(bodyArea.value, "Body JSON");
  body.file = base64;
  body.filename = file.name;
  bodyArea.value = pretty(body);
  showToast("PDF added to the request body.");
}

function readFileAsBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(",")[1] || "");
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(file);
  });
}

async function runEndpoint(endpoint) {
  try {
    const payload = readRunnerPayload(endpoint);

    if (endpoint.danger) {
      const preflight = await fetch("/api/run", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(state.localToken ? { "X-Local-Token": state.localToken } : {}),
          ...(state.csrfToken ? { "X-CSRF-Token": state.csrfToken } : {})
        },
        body: JSON.stringify(payload)
      });
      const preflightData = await preflight.json().catch(() => ({}));
      if (preflight.status === 428 && preflightData.confirmToken) {
        payload.confirmToken = preflightData.confirmToken;
        const confirmation = await promptDangerousConfirmation(endpoint, payload);
        if (!confirmation) {
          showToast("Action cancelled.");
          return;
        }
      } else if (!preflight.ok) {
        throw new Error(preflightData.error || `Precondition check failed with ${preflight.status}`);
      }
    }



    const meta = document.getElementById("responseMeta");
    const output = document.getElementById("responseOutput");
    meta.textContent = "Sending request";
    output.textContent = pretty({ status: "Sending", path: payload.path });

    const result = await api("/api/run", {
      method: "POST",
      body: JSON.stringify(payload)
    });

    state.lastResponse = result;
    meta.textContent = `${result.status || "network"} in ${result.durationMs || 0} ms`;
    output.textContent = pretty(result.data ?? result);
    await loadHistory();
    renderSummary();
    renderHistory();
    showToast(result.ok ? "Request completed." : "Request returned an error.");
  } catch (error) {
    document.getElementById("responseMeta").textContent = "Local error";
    document.getElementById("responseOutput").textContent = pretty({ error: error.message });
    showToast(error.message);
  }
}

function readRunnerPayload(endpoint) {
  const path = document.getElementById("resolvedPathInput").value.trim();
  if (!path.startsWith("/")) {
    throw new Error("Request path must start with /");
  }
  if (path.includes("{") || path.includes("}")) {
    throw new Error("Fill the path variables before sending.");
  }

  const query = parseJson(document.getElementById("queryJson").value, "Query JSON");
  const bodyArea = document.getElementById("bodyJson");
  const hasBody = bodyArea && !bodyArea.closest(".hidden");
  const body = hasBody ? parseJson(bodyArea.value, "Body JSON") : null;

  return {
    endpointId: endpoint.id,
    method: endpoint.method,
    path,
    query,
    body
  };
}

async function savePayload(endpoint) {
  try {
    const payload = readRunnerPayload(endpoint);
    const name = window.prompt("Name this saved payload", endpoint.summary);
    if (!name) {
      return;
    }
    await api("/api/saved-payloads", {
      method: "POST",
      body: JSON.stringify({
        endpoint_id: endpoint.id,
        name,
        method: payload.method,
        path: payload.path,
        query: payload.query,
        body: payload.body || {}
      })
    });
    await loadSavedPayloads();
    renderSummary();
    renderSavedPayloads();
    showToast("Payload saved.");
  } catch (error) {
    showToast(error.message);
  }
}

async function copyCurl(endpoint) {
  try {
    const payload = readRunnerPayload(endpoint);
    const url = buildFullUrl(state.settings.baseUrl, payload.path, payload.query);
    const parts = [`curl -X ${payload.method} "${url}"`, `  -H "Authorization: Bearer YOUR_API_KEY"`];
    if (payload.body !== null) {
      parts.push(`  -H "Content-Type: application/json"`);
      parts.push(`  -d '${JSON.stringify(payload.body).replaceAll("'", "'\\''")}'`);
    }
    await navigator.clipboard.writeText(parts.join(" \\\n"));
    showToast("cURL copied.");
  } catch (error) {
    showToast(error.message);
  }
}

async function saveSettings() {
  try {
    const baseUrl = refs.baseUrlInput.value.trim();
    const apiKey = refs.apiKeyInput.value.trim();
    state.settings = await api("/api/settings", {
      method: "PUT",
      body: JSON.stringify({ baseUrl, apiKey })
    });
    await loadSettings();
    renderSettingsState();
    showToast("Settings saved.");
  } catch (error) {
    showToast(error.message);
  }
}

async function clearApiKey() {
  try {
    state.settings = await api("/api/settings/api-key", { method: "DELETE" });
    await loadSettings();
    renderSettingsState();
    showToast("API key cleared.");
  } catch (error) {
    showToast(error.message);
  }
}

async function clearHistory() {
  if (!window.confirm("Clear local request history?")) {
    return;
  }
  await api("/api/history", { method: "DELETE" });
  await loadHistory();
  renderHistory();
  showToast("History cleared.");
}

function renderHistory() {
  refs.historyRows.innerHTML = state.history.length
    ? state.history.map(historyRowHtml).join("")
    : `<tr><td colspan="5">No requests match criteria.</td></tr>`;

  if (refs.historyPageInfo) {
    refs.historyPageInfo.textContent = `Page ${state.historyPage} of ${state.historyTotalPages} (${state.historyTotal} total)`;
  }
  if (refs.historyPrevBtn) {
    refs.historyPrevBtn.disabled = state.historyPage <= 1;
  }
  if (refs.historyNextBtn) {
    refs.historyNextBtn.disabled = state.historyPage >= state.historyTotalPages;
  }
}

function historyRowHtml(row) {
  const status = row.status || "network";
  return `
    <tr>
      <td>${escapeHtml(formatTime(row.created_at))}</td>
      <td><span class="method ${row.method.toLowerCase()}">${escapeHtml(row.method)}</span></td>
      <td><code>${escapeHtml(row.path)}</code></td>
      <td>${escapeHtml(String(status))}</td>
      <td>${escapeHtml(String(row.duration_ms))} ms</td>
    </tr>
  `;
}

function renderSavedPayloads() {
  refs.savedPayloadList.innerHTML = state.savedPayloads.length
    ? state.savedPayloads.map(savedPayloadHtml).join("")
    : `<div class="empty-state"><h3>No saved payloads</h3><p>Save common request bodies from any endpoint runner.</p></div>`;

  refs.savedPayloadList.querySelectorAll("[data-load-payload]").forEach((button) => {
    button.addEventListener("click", () => loadSavedPayload(button.dataset.loadPayload));
  });
  refs.savedPayloadList.querySelectorAll("[data-delete-payload]").forEach((button) => {
    button.addEventListener("click", () => deleteSavedPayload(button.dataset.deletePayload));
  });
}

function savedPayloadHtml(record) {
  const endpoint = findEndpoint(record.endpoint_id);
  return `
    <div class="saved-item">
      <div>
        <strong>${escapeHtml(record.name)}</strong>
        <p class="meta-line">
          ${escapeHtml(record.method)} ${escapeHtml(record.path)}
          ${endpoint ? ` - ${escapeHtml(endpoint.summary)}` : ""}
        </p>
      </div>
      <div class="inline-actions">
        <button class="button" type="button" data-load-payload="${record.id}">Load</button>
        <button class="button danger" type="button" data-delete-payload="${record.id}">Delete</button>
      </div>
    </div>
  `;
}

function loadSavedPayload(id) {
  const record = state.savedPayloads.find((item) => String(item.id) === String(id));
  if (!record) {
    return;
  }
  const endpoint = findEndpoint(record.endpoint_id);
  if (!endpoint) {
    showToast("The endpoint for this payload is no longer in the catalog.");
    return;
  }
  state.activeGroup = endpoint.group;
  state.selectedEndpointId = endpoint.id;
  state.view = "endpoints";
  render();
  document.getElementById("resolvedPathInput").value = record.path;
  document.getElementById("queryJson").value = pretty(JSON.parse(record.query_json || "{}"));
  const bodyArea = document.getElementById("bodyJson");
  if (bodyArea) {
    bodyArea.value = pretty(JSON.parse(record.body_json || "{}"));
  }
  showToast("Payload loaded.");
}

async function deleteSavedPayload(id) {
  await api(`/api/saved-payloads/${encodeURIComponent(id)}`, { method: "DELETE" });
  await loadSavedPayloads();
  renderSummary();
  renderSavedPayloads();
  showToast("Payload deleted.");
}

function setView(view) {
  state.view = view === "history" || view === "database" ? view : "endpoints";
  refs.endpointView.hidden = state.view !== "endpoints";
  refs.historyView.hidden = state.view !== "history";
  refs.databaseView.hidden = state.view !== "database";
}

function findEndpoint(id) {
  return state.endpoints.find((endpoint) => endpoint.id === id);
}

function parseJson(text, label) {
  const trimmed = text.trim();
  if (!trimmed) {
    return {};
  }
  try {
    return JSON.parse(trimmed);
  } catch (error) {
    throw new Error(`${label} is not valid JSON.`);
  }
}

function pretty(value) {
  return JSON.stringify(value, null, 2);
}

function buildFullUrl(baseUrl, path, query) {
  const params = new URLSearchParams();
  Object.entries(query || {}).forEach(([key, value]) => {
    if (value === "" || value === null || value === undefined) {
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((item) => params.append(key, item));
    } else {
      params.append(key, value);
    }
  });
  const suffix = params.toString();
  return `${baseUrl.replace(/\/$/, "")}${path}${suffix ? `?${suffix}` : ""}`;
}

function formatTime(value) {
  if (!value) {
    return "";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

let toastTimer;
function showToast(message) {
  refs.toast.textContent = message;
  refs.toast.classList.add("show");
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => refs.toast.classList.remove("show"), 2600);
}
