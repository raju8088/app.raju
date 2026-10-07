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
  localToken: "",
  session: null,
  transitioning: false,
  submissions: {},
  actionFilter: "all",
  drafts: {},
  responses: {},
  runnerId: null,
  running: false,
  historyLoading: false,
  historyError: "",
  savedError: "",
  historySequence: 0
};

const refs = {};

document.addEventListener("DOMContentLoaded", init);

async function init() {
  cacheRefs();
  bindStaticEvents();
  try {
    applyTheme(localStorage.getItem("omni-theme") || "light");
  } catch { applyTheme("light"); }
  await bootstrap();
}

async function loadSession() {
  const hash = window.location.hash || "";
  if (hash.includes("token=")) {
    const match = hash.match(/token=([^&]+)/);
    if (match) {
      state.localToken = decodeURIComponent(match[1]);
      history.replaceState(null, "", window.location.pathname + window.location.search);
    }
  }

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

  const data = await api("/api/session");
  state.session = data;
  state.csrfToken = data.csrfToken || state.csrfToken;
  state.localToken = data.hosted ? "" : data.localToken || state.localToken;
  renderAccount();
}

function renderAccount() {
  const session = state.session;
  refs.accountBar.hidden = !session?.hosted;
  if (!session?.hosted) return;
  refs.accountName.textContent = session.user?.username || "Signed in";
  refs.accountRole.textContent = session.role || "Member";
  refs.workspaceSelect.innerHTML = (session.workspaces || []).map(workspace =>
    `<option value="${escapeHtml(workspace.id)}">${escapeHtml(workspace.name)}</option>`).join("");
  refs.workspaceSelect.value = String(session.workspace?.id || "");
  refs.workspaceSelect.disabled = (session.workspaces || []).length < 2;
}

function clearWorkspaceData() {
  state.drafts = {};
  state.responses = {};
  state.submissions = {};
  state.history = [];
  state.savedPayloads = [];
  state.runnerId = null;
  state.csrfToken = "";
  state.localToken = "";
  refs.apiKeyInput.value = "";
  refs.endpointDetail.replaceChildren();
  refs.historyRows.replaceChildren();
  refs.savedPayloadList.replaceChildren();
  const dialog = document.getElementById("dangerDialog");
  if (dialog?.open) dialog.close();
}

function requireSignIn() {
  if (state.signInRedirect) return;
  state.signInRedirect = true;
  state.transitioning = true;
  clearWorkspaceData();
  window.location.replace("/login/?next=%2F");
}

async function switchWorkspace() {
  if (state.running || state.transitioning) return;
  const workspaceId = refs.workspaceSelect.value;
  state.transitioning = true;
  refs.workspaceSelect.disabled = true;
  try {
    await api("/api/workspace", { method: "POST", body: JSON.stringify({ workspaceId }) });
    clearWorkspaceData();
    window.location.reload();
  } catch (error) {
    state.transitioning = false;
    renderAccount();
    showToast(error.message);
  }
}

async function logout() {
  if (state.transitioning || state.running) return;
  refs.logoutBtn.disabled = true;
  try {
    await api("/api/logout", { method: "POST", body: "{}" });
    requireSignIn();
  } catch (error) {
    refs.logoutBtn.disabled = false;
    showToast(`Could not sign out. ${error.message}`);
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
    "retentionLimitInput",
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
    "toast", "themeToggleBtn", "openSettingsBtn", "settingsPanel", "workspaceNotice",
    "noticeTitle", "noticeMessage", "retryLoadBtn", "actionFilter", "actionCount",
    "historyStatus", "savedStatus", "refreshHistoryBtn", "accountBar", "accountName",
    "accountRole", "workspaceSelect", "logoutBtn", "settingsAccessNote"
  ].forEach((id) => {
    refs[id] = document.getElementById(id);
  });
}

function bindStaticEvents() {
  refs.workspaceSelect.addEventListener("change", switchWorkspace);
  refs.logoutBtn.addEventListener("click", logout);
  refs.themeToggleBtn.addEventListener("click", () => {
    const theme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    applyTheme(theme);
    try { localStorage.setItem("omni-theme", theme); } catch { /* Appearance still works without storage. */ }
  });
  refs.openSettingsBtn.addEventListener("click", () => {
    refs.settingsPanel.open = !refs.settingsPanel.open;
    if (refs.settingsPanel.open) refs.baseUrlInput.focus();
  });
  refs.retryLoadBtn.addEventListener("click", bootstrap);
  refs.refreshHistoryBtn.addEventListener("click", () => loadHistory(state.historyPage));
  refs.actionFilter.addEventListener("change", () => {
    state.actionFilter = refs.actionFilter.value;
    renderEndpointList();
  });
  let historySearchTimer;
  refs.searchInput.addEventListener("input", renderEndpointList);
  refs.saveSettingsBtn.addEventListener("click", saveSettings);
  refs.clearKeyBtn.addEventListener("click", clearApiKey);
  refs.clearHistoryBtn.addEventListener("click", clearHistory);
  refs.historySearchInput?.addEventListener("input", (e) => {
    state.historySearch = e.target.value.trim();
    clearTimeout(historySearchTimer);
    historySearchTimer = setTimeout(() => loadHistory(1), 250);
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
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (state.localToken) headers["X-Local-Token"] = state.localToken;
  if (state.session?.hosted && state.session.workspace?.id && !["/api/session", "/api/workspace", "/api/logout"].includes(path)) {
    headers["X-Workspace-ID"] = String(state.session.workspace.id);
  }
  if (["POST", "PUT", "PATCH", "DELETE"].includes(method) && state.csrfToken) headers["X-CSRF-Token"] = state.csrfToken;
  const response = await fetch(path, { credentials: "same-origin", cache: "no-store", ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401) requireSignIn();
    if (response.status === 409 && data.code === "workspace_changed") {
      clearWorkspaceData();
      window.location.reload();
    }
    const error = new Error(data.error || data.detail || data.data?.error || `Request failed (${response.status}).`);
    error.status = response.status;
    error.payload = data;
    throw error;
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
    ? state.settings.apiKeyPreview ? `Saved ${state.settings.apiKeyPreview}` : "API key configured"
    : "Paste key to save";
  if (refs.readOnlyBadge) {
    refs.readOnlyBadge.hidden = !state.settings.readOnly;
  }
  if (refs.retentionLimitInput) {
    refs.retentionLimitInput.value = state.settings.retentionLimit || 5000;
  }
}


async function loadHistory(page = 1) {
  const sequence = ++state.historySequence;
  const q = new URLSearchParams({ page: String(page), limit: String(state.historyLimit) });
  if (state.historySearch) q.set("search", state.historySearch);
  state.historyLoading = true;
  state.historyError = "";
  renderHistory();
  try {
    const data = await api(`/api/history?${q.toString()}`);
    if (sequence !== state.historySequence) return;
    state.history = data.items || data.records || [];
    state.historyPage = data.page || page;
    state.historyTotal = data.total ?? state.history.length;
    state.historyTotalPages = data.totalPages || 1;
  } catch (error) {
    if (sequence !== state.historySequence) return;
    state.historyError = `History could not refresh. ${error.message} Use Refresh to try again.`;
  } finally {
    if (sequence === state.historySequence) {
      state.historyLoading = false;
      renderHistory();
    }
  }
}

async function loadSavedPayloads() {
  state.savedError = "";
  try {
    const data = await api("/api/saved-payloads");
    state.savedPayloads = data.records || [];
  } catch (error) {
    state.savedError = `Saved requests could not load. ${error.message} Retry loading the workspace.`;
  }
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
  const canManageSettings = state.settings.canManageSettings ?? !state.settings.readOnly;
  refs.connectionDot.classList.toggle("ready", state.settings.hasApiKey);
  refs.connectionDot.classList.toggle("missing", !state.settings.hasApiKey);
  refs.connectionLabel.textContent = state.settings.hasApiKey ? "API key configured" : "Connection setup needed";
  refs.connectionDetail.textContent = state.settings.hasApiKey
    ? "Ready to send a request. Connection not yet verified."
    : canManageSettings ? "Open connection settings to add your API key." : "Ask a workspace administrator to connect an API key.";
  [refs.saveSettingsBtn, refs.clearKeyBtn].forEach(button => { button.disabled = !canManageSettings; });
  [refs.baseUrlInput, refs.apiKeyInput, refs.retentionLimitInput].forEach(input => { input.disabled = !canManageSettings; });
  refs.clearHistoryBtn.disabled = !!state.settings.readOnly || (state.session?.hosted && state.session.role !== "admin");
  refs.settingsAccessNote.hidden = canManageSettings;
  refs.settingsAccessNote.textContent = "Only workspace administrators can update the connection and history settings.";
  refs.readOnlyBadge.hidden = !state.settings.readOnly;
  if (state.settings.readOnly) {
    showNotice("Read-only workspace", "You can run read actions and review activity. Changes to data and settings are restricted.");
  } else if (!state.settings.hasApiKey) {
    showNotice("Connect your account to get started", canManageSettings ? "Explore the action library, then add your API key in connection settings to send a request." : "Ask your workspace administrator to add an API key. You can explore the action library while setup is completed.");
  } else {
    refs.workspaceNotice.hidden = true;
  }
  syncSendState();
}

function renderGroupNav() {
  refs.groupNav.innerHTML = state.groups
    .map((group) => {
      const count = group.endpoints.length;
      const active = group.name === state.activeGroup ? "active" : "";
      return `
        <button class="group-button ${active}" type="button" aria-current="${state.view === "endpoints" && active ? "page" : "false"}" data-group="${escapeHtml(group.name)}">
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
    const matchesType = state.actionFilter === "all"
      || (state.actionFilter === "read" && endpoint.method === "GET")
      || (state.actionFilter === "write" && endpoint.method !== "GET")
      || (state.actionFilter === "protected" && endpoint.danger);
    return haystack.includes(search) && matchesType;
  });

  refs.groupTitle.textContent = search ? "Search results" : state.activeGroup;
  refs.groupDescription.textContent = search
    ? `${filtered.length} matching endpoint${filtered.length === 1 ? "" : "s"}`
    : currentGroup?.description || "";

  refs.actionCount.textContent = `${filtered.length} actions`;
  refs.endpointList.setAttribute("aria-busy", "false");
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
      if (window.matchMedia("(max-width: 950px)").matches) {
        refs.endpointDetail.scrollIntoView({ block: "start", behavior: "smooth" });
      }
    });
  });
}

function endpointButtonHtml(endpoint) {
  const active = endpoint.id === state.selectedEndpointId ? "active" : "";
  const danger = endpoint.danger ? `<span class="endpoint-note">Protected action</span>` : "";
  return `
    <button class="endpoint-item ${active}" type="button" aria-pressed="${!!active}" data-endpoint-id="${escapeHtml(endpoint.id)}">
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
  captureDraft();
  const endpoint = findEndpoint(state.selectedEndpointId);
  if (!endpoint) {
    refs.endpointDetail.className = "empty-state";
    refs.endpointDetail.innerHTML = `<h2>Select an endpoint</h2><p>Choose the next action from the sequence to build and send a request.</p>`;
    return;
  }

  const draft = state.drafts[endpoint.id];
  const queryText = draft?.query ?? pretty(endpoint.queryExample || {});
  const showBody = ["POST", "PUT", "PATCH", "DELETE"].includes(endpoint.method);
  const bodyText = draft?.body ?? pretty(endpoint.bodyExample ?? {});
  const pathFields = endpoint.pathParams
    .map(
      (param) => `
        <label>
          <span>${escapeHtml(param)}</span>
          <input class="path-param" data-param="${escapeHtml(param)}" type="text" placeholder="Enter ${escapeHtml(param)}" value="${escapeHtml(draft?.params?.[param] || "")}">
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
      <p>${endpoint.method === "GET" ? "Read data without changing it." : "Prepare your request and review the result below."} Your API key is added securely by the server.</p>
    </div>

    <div class="form-area">
      ${endpoint.note ? `<p class="meta-line">${escapeHtml(endpoint.note)}</p>` : ""}
      <label>
        <span>Request path</span>
        <input id="resolvedPathInput" type="text" value="${escapeHtml(draft?.path || endpoint.path)}" autocomplete="off" readonly>
        <p class="field-help">${pathFields ? "Fill the identifiers below to complete this path." : "This path is fixed for the selected action."}</p>
      </label>

      ${pathFields ? `<div class="field-grid">${pathFields}</div>` : ""}

      ${endpoint.path === "/knowledge_base/create" ? fileHelperHtml() : ""}

      <div class="textarea-grid">
        <div class="text-panel">
          <div class="text-panel-header"><label for="queryJson">Query parameters</label><button class="format-button" type="button" data-format="queryJson">Format JSON</button></div>
          <textarea id="queryJson" spellcheck="false" aria-describedby="queryJsonNote">${escapeHtml(queryText)}</textarea><p id="queryJsonNote" class="validation-note"></p>
        </div>
        <div class="text-panel ${showBody ? "" : "hidden"}">
          <div class="text-panel-header"><label for="bodyJson">Request body</label><button class="format-button" type="button" data-format="bodyJson">Format JSON</button></div>
          <textarea id="bodyJson" spellcheck="false" aria-describedby="bodyJsonNote">${escapeHtml(bodyText)}</textarea><p id="bodyJsonNote" class="validation-note"></p>
        </div>
      </div>

      ${endpoint.danger ? dangerBoxHtml(endpoint) : ""}

      <div class="inline-actions request-actions">
        <button id="sendRequestBtn" class="button primary" type="button">Send request</button>
        <button id="savePayloadBtn" class="button" type="button">Save request</button>
        <button id="copyCurlBtn" class="button" type="button">Copy cURL</button>
        <button id="resetFormBtn" class="button subtle" type="button">Reset draft</button>
      </div>
    </div>

    <div class="response-panel">
      <div class="response-head">
        <strong>Response</strong>
        <span id="responseMeta" class="response-meta" role="status" aria-live="polite">Ready when you are</span>
      </div>
      <pre id="responseOutput">Send a request to see its result here.</pre>
    </div>
  `;

  state.runnerId = endpoint.id;
  bindRunnerEvents(endpoint);
  ["queryJson", "bodyJson"].forEach(validateEditor);
  const response = state.responses[endpoint.id];
  if (response) updateRunnerStatus(endpoint, response.message, response.data, response.tone);
  syncSendState();
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

function dangerBoxHtml() {
  return `<div class="danger-box"><strong>Review required before sending</strong><p>This action may place calls, create costs or change live resources. You will review the exact request and confirm before it runs.</p></div>`;
}

function bindRunnerEvents(endpoint) {
  document.getElementById("sendRequestBtn").addEventListener("click", () => runEndpoint(endpoint));
  document.getElementById("savePayloadBtn").addEventListener("click", () => savePayload(endpoint));
  document.getElementById("copyCurlBtn").addEventListener("click", () => copyCurl(endpoint));
  document.getElementById("resetFormBtn").addEventListener("click", () => {
    if (!confirm("Reset this draft to the example request?")) return;
    delete state.drafts[endpoint.id];
    state.runnerId = null;
    renderRunner();
  });
  document.getElementById("savePayloadBtn").disabled = !!state.settings.readOnly;
  document.querySelectorAll("[data-format]").forEach(button => button.addEventListener("click", () => {
    const editor = document.getElementById(button.dataset.format);
    try { editor.value = pretty(parseJson(editor.value, "Request JSON")); validateEditor(editor.id); }
    catch (error) { validateEditor(editor.id); editor.focus(); showToast(error.message); }
  }));
  ["queryJson", "bodyJson"].forEach(id => document.getElementById(id).addEventListener("input", () => validateEditor(id)));

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
  syncSendState();
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

function promptDangerousConfirmation(endpoint, payload, review = {}) {
  const phrase = review.requiredConfirm || endpoint.summary;
  const seconds = Math.max(1, Math.min(300, Number(review.expiresInSeconds) || 60));
  return new Promise(resolve => {
    const dialog = document.getElementById("dangerDialog");
    if (!dialog || typeof dialog.showModal !== "function") {
      resolve(confirm(`Confirm ${endpoint.summary}?\n${buildFullUrl(state.settings.baseUrl, payload.path, payload.query)}`) ? phrase : null);
      return;
    }
    const input = document.getElementById("modalConfirmInput");
    const confirmBtn = document.getElementById("modalConfirmBtn");
    const cancelBtn = document.getElementById("modalCancelBtn");
    const previousFocus = document.activeElement;
    document.getElementById("modalActionTitle").textContent = endpoint.summary;
    document.getElementById("modalImpactText").textContent = getEstimatedImpact(endpoint, payload.path);
    document.getElementById("modalMethod").textContent = endpoint.method;
    document.getElementById("modalUrl").textContent = buildFullUrl(state.settings.baseUrl, payload.path, payload.query);
    document.getElementById("modalBodyPreview").textContent = pretty({ query: payload.query, body: payload.body });
    document.getElementById("modalPromptText").textContent = `Type “${phrase}” to confirm. This review expires in ${seconds} seconds.`;
    input.value = "";
    confirmBtn.disabled = true;
    let settled = false;
    const onInput = () => { confirmBtn.disabled = input.value.trim() !== phrase; };
    const finish = value => {
      if (settled) return;
      settled = true;
      clearTimeout(expiry);
      input.removeEventListener("input", onInput);
      dialog.removeEventListener("cancel", onCancel);
      dialog.removeEventListener("close", onClose);
      confirmBtn.onclick = cancelBtn.onclick = null;
      if (dialog.open) dialog.close();
      previousFocus?.focus();
      resolve(value);
    };
    const onCancel = event => { event.preventDefault(); finish(null); };
    const onClose = () => finish(null);
    const expiry = setTimeout(() => { finish(null); showToast("Confirmation expired. Send again to review a fresh request."); }, seconds * 1000);
    input.addEventListener("input", onInput);
    dialog.addEventListener("cancel", onCancel);
    dialog.addEventListener("close", onClose);
    confirmBtn.onclick = () => finish(phrase);
    cancelBtn.onclick = () => finish(null);
    dialog.showModal();
    input.focus();
  });
}

async function addPdfToBody() {
  const button = document.getElementById("loadPdfBtn");
  try {
    const file = document.getElementById("knowledgeFileInput").files[0];
    if (!file) throw new Error("Choose a PDF first.");
    if (!file.name.toLowerCase().endsWith(".pdf") || (file.type && file.type !== "application/pdf")) throw new Error("Choose a PDF document.");
    if (file.size > 7 * 1024 * 1024) throw new Error("Choose a PDF smaller than 7 MB.");
    if (!(await file.slice(0, 5).text()).startsWith("%PDF-")) throw new Error("This file does not appear to be a PDF.");
    button.disabled = true;
    button.textContent = "Reading PDF…";
    const bodyArea = document.getElementById("bodyJson");
    const body = parseJson(bodyArea.value, "Request body");
    if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("Request body must be a JSON object.");
    body.file = await readFileAsBase64(file);
    body.filename = file.name;
    bodyArea.value = pretty(body);
    validateEditor("bodyJson");
    showToast("PDF attached to this request.");
  } catch (error) { showToast(error.message); }
  finally { button.disabled = false; button.textContent = "Add to body"; }
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
  if (state.running || state.transitioning) return;
  if (requiresAdministrator(endpoint)) return;
  if (!state.settings.hasApiKey || (state.settings.readOnly && endpoint.method !== "GET")) return;
  let submitted = false;
  let fingerprint;
  let submission;
  let storageKey;
  try {
    let payload = readRunnerPayload(endpoint);
    fingerprint = JSON.stringify(payload);
    const mutating = endpoint.method !== "GET";
    captureDraft();
    state.running = true;
    syncSendState();
    submission = state.submissions[fingerprint];
    if (mutating) {
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(fingerprint));
      const requestHash = [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, "0")).join("");
      storageKey = `omni-submission:${state.session?.user?.id || "local"}:${state.session?.workspace?.id || "local"}:${requestHash}`;
      if (!submission) {
        try {
          const key = sessionStorage.getItem(storageKey);
          if (key && /^[a-f0-9-]{36}$/.test(key)) submission = state.submissions[fingerprint] = { key, payload, uncertain: true };
        } catch { /* In-memory retry protection remains available if browser storage is blocked. */ }
      }
    }
    if (!submission) {
      updateRunnerStatus(endpoint, "Preparing review…", "Checking the request before confirmation.", "");
      const review = await api("/api/preflight", { method: "POST", body: JSON.stringify(payload) });
      if (review.danger || review.confirmToken) {
        if (!review.confirmToken) throw new Error("The server could not prepare a protected-action review.");
        const phrase = await promptDangerousConfirmation(endpoint, payload, review);
        if (!phrase) {
          updateRunnerStatus(endpoint, "Cancelled — no request sent", "You can edit this draft and send it again.", "");
          return;
        }
        payload.confirmToken = review.confirmToken;
        payload.confirmText = phrase;
      }
      if (mutating) {
        submission = state.submissions[fingerprint] = { key: crypto.randomUUID(), payload };
        try { sessionStorage.setItem(storageKey, submission.key); } catch { /* The current page still retains this identifier. */ }
      }
    } else {
      payload = submission.payload;
    }
    updateRunnerStatus(endpoint, submission?.uncertain ? "Checking previous request…" : "Sending request…", "Waiting for the server. Keep this page open while the request is in progress.", "");
    submitted = true;
    const result = await api("/api/run", { method: "POST", body: JSON.stringify(payload), headers: submission ? { "Idempotency-Key": submission.key } : {} });
    if (result.code === "operation_uncertain" || result.code === "operation_pending") {
      const error = new Error(result.error || "The previous request outcome is still being checked.");
      error.payload = result;
      error.status = 409;
      throw error;
    }
    delete state.submissions[fingerprint];
    if (storageKey) { try { sessionStorage.removeItem(storageKey); } catch { /* Storage may be unavailable. */ } }
    state.lastResponse = result;
    updateRunnerStatus(endpoint, `${result.ok ? "Completed" : "Request failed"} · ${result.status || "network"} · ${result.durationMs || 0} ms${result.warning ? " · See warning" : ""}`, result.warning ? { warning: result.warning, data: result.data, operationId: result.operationId } : result.data ?? result, result.ok ? "success" : "error");
    await loadHistory();
    renderSummary();
    showToast(result.ok ? `${endpoint.summary}: completed.` : "Request failed. Review the response for details.");
  } catch (error) {
    const result = error.payload;
    const uncertain = submitted && submission && (!error.status || error.status >= 500 || ["operation_uncertain", "operation_pending", "response_expired", "idempotency_conflict"].includes(result?.code));
    if (uncertain) {
      submission.uncertain = true;
      updateRunnerStatus(endpoint, result?.code === "operation_pending" ? "Request still in progress" : "Outcome not yet confirmed", {
        message: "Check the previous request below to retrieve its result safely. The same submission identifier will be reused. If the outcome remains unknown, check the provider before starting another action.",
        operationId: result?.operationId || submission.key,
        details: result || { error: error.message }
      }, "error");
    } else {
      if (fingerprint) delete state.submissions[fingerprint];
      if (storageKey) { try { sessionStorage.removeItem(storageKey); } catch { /* Storage may be unavailable. */ } }
      updateRunnerStatus(endpoint, submitted ? "Request error — review before repeating" : "Check your request", result || { error: error.message }, "error");
    }
    showToast(error.message);
  } finally {
    state.running = false;
    syncSendState();
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

  const pattern = "^" + endpoint.path.split(/(\{[^}]+\})/).map(part => part.startsWith("{") ? "[^/?#]+" : part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("") + "$";
  if (!new RegExp(pattern).test(path) || /[?#]|\.\.|%2f|%5c|%2e/i.test(path)) throw new Error("The request path must match the selected action. Check its identifiers.");
  const query = parseJson(document.getElementById("queryJson").value, "Query JSON");
  if (!query || typeof query !== "object" || Array.isArray(query)) throw new Error("Query parameters must be a JSON object.");
  const bodyArea = document.getElementById("bodyJson");
  const hasBody = bodyArea && !bodyArea.closest(".hidden");
  const body = hasBody ? parseJson(bodyArea.value, "Body JSON") : null;

  const reusableValues = JSON.stringify({ query, body });
  if (reusableValues.includes("[REDACTED]") || reusableValues.includes("[BASE64_FILE:")) throw new Error("Re-enter omitted credentials or reattach the file before sending this saved request.");
  return {
    endpointId: endpoint.id,
    method: endpoint.method,
    path,
    query,
    body
  };
}

async function savePayload(endpoint) {
  if (state.settings.readOnly || state.transitioning) return;
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
    const parts = [`curl -X ${payload.method} ${shellQuote(url)}`, `  -H "Authorization: Bearer YOUR_API_KEY"`];
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
  if (state.settings.canManageSettings === false || state.settings.readOnly || state.running || state.transitioning) return;
  try {
    const baseUrl = refs.baseUrlInput.value.trim();
    const apiKey = refs.apiKeyInput.value.trim();
    const retentionLimit = parseInt(refs.retentionLimitInput?.value, 10);
    const bodyObj = { baseUrl };
    if (apiKey) {
      bodyObj.apiKey = apiKey;
    }
    if (!Number.isNaN(retentionLimit)) {
      bodyObj.retentionLimit = retentionLimit;
    }
    state.settings = await api("/api/settings", {
      method: "PUT",
      body: JSON.stringify(bodyObj)
    });
    await loadSettings();
    renderSettingsState();
    showToast("Settings saved.");
  } catch (error) {
    showToast(error.message);
  }
}

async function clearApiKey() {
  if (state.settings.canManageSettings === false || state.settings.readOnly || state.running || state.transitioning) return;
  if (!confirm("Remove the saved API key? You can add it again in connection settings.")) return;
  try {
    state.settings = await api("/api/settings/api-key", { method: "DELETE" });
    await loadSettings();
    renderSettingsState();
    showToast(state.settings.hasApiKey ? "Saved key removed. A key is still supplied by the server environment." : "Saved API key removed.");
  } catch (error) {
    showToast(error.message);
  }
}

async function clearHistory() {
  if (refs.clearHistoryBtn.disabled || state.transitioning) return;
  if (!confirm("Clear request history for this workspace? This cannot be undone.")) return;
  try {
    await api("/api/history", { method: "DELETE" });
    await loadHistory();
    showToast("History cleared.");
  } catch (error) { showToast(error.message); }
}

function renderHistory() {
  refs.historyStatus.hidden = !state.historyError && !state.historyLoading;
  refs.historyStatus.textContent = state.historyError || "Refreshing history…";
  refs.historyRows.setAttribute("aria-busy", String(state.historyLoading));
  refs.refreshHistoryBtn.disabled = state.historyLoading;
  refs.historyRows.innerHTML = state.history.length
    ? state.history.map(historyRowHtml).join("")
    : `<tr><td colspan="5">${state.historyError ? "History is unavailable. Use Refresh to try again." : state.historyLoading ? "Loading history…" : "No requests yet. Send an action or try a different search."}</td></tr>`;

  if (refs.historyPageInfo) {
    refs.historyPageInfo.textContent = `Page ${state.historyPage} of ${state.historyTotalPages} (${state.historyTotal} total)`;
  }
  if (refs.historyPrevBtn) {
    refs.historyPrevBtn.disabled = state.historyLoading || state.historyPage <= 1;
  }
  if (refs.historyNextBtn) {
    refs.historyNextBtn.disabled = state.historyLoading || state.historyPage >= state.historyTotalPages;
  }
}

function historyRowHtml(row) {
  const status = row.status || "network";
  return `
    <tr>
      <td>${escapeHtml(formatTime(row.created_at))}</td>
      <td><span class="method ${row.method.toLowerCase()}">${escapeHtml(row.method)}</span></td>
      <td><code>${escapeHtml(row.path)}</code></td>
      <td><span class="status-label ${row.ok ? "" : "error"}">${escapeHtml(String(status))} · ${row.ok ? "Success" : "Failed"}</span></td>
      <td>${escapeHtml(String(row.duration_ms))} ms</td>
    </tr>
  `;
}

function renderSavedPayloads() {
  refs.savedStatus.hidden = !state.savedError;
  refs.savedStatus.textContent = state.savedError;
  refs.savedPayloadList.innerHTML = state.savedPayloads.length
    ? state.savedPayloads.map(savedPayloadHtml).join("")
    : `<div class="empty-state"><h3>${state.savedError ? "Saved requests unavailable" : "Build your request library"}</h3><p>${state.savedError ? "Retry loading the workspace to see your saved requests." : "Prepare an action and choose Save request to reuse it later."}</p></div>`;

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
        <button class="button danger" type="button" data-delete-payload="${record.id}" ${state.settings.readOnly ? "disabled" : ""}>Delete</button>
      </div>
    </div>
  `;
}

function loadSavedPayload(id) {
  const record = state.savedPayloads.find(item => String(item.id) === String(id));
  if (!record) return;
  const endpoint = findEndpoint(record.endpoint_id);
  if (!endpoint) { showToast("This action is no longer available in the catalog."); return; }
  try {
    const query = JSON.parse(record.query_json || "{}");
    const body = JSON.parse(record.body_json || "{}");
    captureDraft();
    const segments = record.path.split("/");
    const params = {};
    endpoint.path.split("/").forEach((part, index) => {
      if (part.startsWith("{")) params[part.slice(1, -1)] = segments[index] || "";
    });
    state.drafts[endpoint.id] = { path: record.path, query: pretty(query), body: pretty(body), params };
    state.runnerId = null;
    state.activeGroup = endpoint.group;
    state.selectedEndpointId = endpoint.id;
    state.view = "endpoints";
    render();
    document.getElementById("resolvedPathInput").scrollIntoView({ block: "center" });
    showToast("Request loaded. Review its values and re-enter omitted credentials or attachments.");
  } catch { showToast("This saved request cannot be read. Its stored JSON may be incomplete."); }
}

async function deleteSavedPayload(id) {
  if (state.settings.readOnly || state.transitioning) return;
  if (!confirm("Delete this saved request? This cannot be undone.")) return;
  try {
    await api(`/api/saved-payloads/${encodeURIComponent(id)}`, { method: "DELETE" });
    await loadSavedPayloads();
    renderSummary();
    renderSavedPayloads();
    showToast("Saved request deleted.");
  } catch (error) { showToast(error.message); }
}

function setView(view) {
  state.view = view === "history" || view === "database" ? view : "endpoints";
  refs.endpointView.hidden = state.view !== "endpoints";
  refs.historyView.hidden = state.view !== "history";
  refs.databaseView.hidden = state.view !== "database";
  document.querySelectorAll("[data-view]").forEach(button => {
    button.classList.toggle("active", button.dataset.view === state.view);
    button.setAttribute("aria-current", button.dataset.view === state.view ? "page" : "false");
  });
  refs.groupNav.querySelectorAll("[data-group]").forEach(button => {
    button.classList.toggle("active", state.view === "endpoints" && button.dataset.group === state.activeGroup);
    button.setAttribute("aria-current", state.view === "endpoints" && button.dataset.group === state.activeGroup ? "page" : "false");
  });
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

async function bootstrap() {
  refs.retryLoadBtn.disabled = true;
  showNotice("Loading workspace", "Getting your actions, settings and recent activity ready.");
  try {
    await loadSession();
    await Promise.all([loadCatalog(), loadSettings()]);
    await Promise.all([loadHistory(), loadSavedPayloads()]);
    state.selectedEndpointId ||= state.endpoints[0]?.id || null;
    render();
    if (state.savedError) showNotice("Some data could not load", state.savedError, true);
  } catch (error) {
    refs.endpointList.setAttribute("aria-busy", "false");
    showNotice("Workspace could not load", `${error.message} Check that the server is running, then try again.`, true);
  } finally { refs.retryLoadBtn.disabled = false; }
}

function showNotice(title, message, retry = false) {
  refs.workspaceNotice.hidden = false;
  refs.workspaceNotice.classList.toggle("error", retry);
  refs.noticeTitle.textContent = title;
  refs.noticeMessage.textContent = message;
  refs.retryLoadBtn.hidden = !retry;
}

function applyTheme(theme) {
  const dark = theme === "dark";
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  refs.themeToggleBtn.textContent = dark ? "Light appearance" : "Dark appearance";
  refs.themeToggleBtn.setAttribute("aria-pressed", String(dark));
}

function captureDraft() {
  if (!state.runnerId || !document.getElementById("queryJson")) return;
  const params = {};
  document.querySelectorAll(".path-param").forEach(input => { params[input.dataset.param] = input.value; });
  state.drafts[state.runnerId] = {
    path: document.getElementById("resolvedPathInput").value,
    query: document.getElementById("queryJson").value,
    body: document.getElementById("bodyJson")?.value || "{}", params
  };
}

function validateEditor(id) {
  const editor = document.getElementById(id);
  const note = document.getElementById(`${id}Note`);
  try {
    const value = parseJson(editor.value, "JSON");
    if (id === "queryJson" && (!value || typeof value !== "object" || Array.isArray(value))) throw new Error("Use a JSON object for query parameters.");
    editor.setAttribute("aria-invalid", "false");
    note.classList.remove("invalid");
    note.textContent = "Valid JSON";
  } catch (error) {
    editor.setAttribute("aria-invalid", "true");
    note.classList.add("invalid");
    note.textContent = error.message;
  }
  syncSendState();
}

function syncSendState() {
  if (refs.workspaceSelect) refs.workspaceSelect.disabled = state.running || state.transitioning || (state.session?.workspaces || []).length < 2;
  if (refs.logoutBtn) refs.logoutBtn.disabled = state.running || state.transitioning;
  if (refs.saveSettingsBtn) refs.saveSettingsBtn.disabled = state.running || state.transitioning || state.settings.canManageSettings === false || !!state.settings.readOnly;
  if (refs.clearKeyBtn) refs.clearKeyBtn.disabled = state.running || state.transitioning || state.settings.canManageSettings === false || !!state.settings.readOnly;
  const button = document.getElementById("sendRequestBtn");
  if (!button) return;
  const endpoint = findEndpoint(state.runnerId);
  const adminOnly = requiresAdministrator(endpoint);
  const writeBlocked = state.settings.readOnly && endpoint?.method !== "GET";
  let pending = false;
  try { pending = !!state.submissions[JSON.stringify(readRunnerPayload(endpoint))]?.uncertain; } catch { /* Invalid drafts are handled by validation. */ }
  const invalid = document.querySelector('.text-panel:not(.hidden) textarea[aria-invalid="true"]');
  button.disabled = state.running || state.transitioning || !state.settings.hasApiKey || writeBlocked || adminOnly || !!invalid;
  button.innerHTML = state.running ? '<span class="spinner" aria-hidden="true"></span> Request in progress' : adminOnly ? "Administrator access required" : writeBlocked ? "Read-only mode" : !state.settings.hasApiKey ? "API key required" : pending ? "Check previous request" : "Send request";
  refs.endpointDetail.setAttribute("aria-busy", String(state.running));
}

function requiresAdministrator(endpoint) {
  return state.session?.hosted && state.session.role !== "admin" && ["Admin", "Reseller", "Reseller/Admin"].includes(endpoint?.group);
}

function updateRunnerStatus(endpoint, message, data, tone) {
  state.responses[endpoint.id] = { message, data, tone };
  if (state.runnerId !== endpoint.id) return;
  const meta = document.getElementById("responseMeta");
  if (!meta) return;
  meta.textContent = message;
  meta.className = `response-meta ${tone}`;
  document.getElementById("responseOutput").textContent = typeof data === "string" ? data : pretty(data);
}

function shellQuote(value) {
  return "'" + String(value).replaceAll("'", "'\\''") + "'";
}
