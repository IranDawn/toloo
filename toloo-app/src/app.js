// ══════════════════════════════════════════════════════════════════════
// Tauri bridge
// ══════════════════════════════════════════════════════════════════════

const IS_TAURI = typeof window.__TAURI__ !== "undefined";

async function invoke(cmd, args = {}) {
  if (!IS_TAURI) throw new Error("Native backend not available in browser mode.");
  return window.__TAURI__.core.invoke(cmd, args);
}


// ══════════════════════════════════════════════════════════════════════
// App state
// ══════════════════════════════════════════════════════════════════════

const state = {
  node:           null,        // null | { sig_pub, enc_pub, node_json }
  relayUrls:      [],          // string[] — relay URLs this client connects to
  rooms:          new Map(),   // room_pub → RoomEntry
  activeRoom:     null,        // room_pub | null
  savedRelays:    [],          // RelayConfigRecord[] from backend DB
  runningRelays:  [],          // RelayInfo[] from backend (live metrics)
  relayPollTimer: null,
  blocklist:      [],          // BlocklistItem[] from backend DB
};

// RelayConfigRecord (from DB):
//   { id, proto, host, port, skin, padding, path, direct, active }
// RelayInfo (running, from relay_list):
//   { runtime_id, config_id, invite_uri, proto, host, port, skin,
//     active (peers), total, bytes_in, bytes_out }

// RoomEntry:
// { pub, name, inviteUri, committedJson, messages, syncAfter }


// ══════════════════════════════════════════════════════════════════════
// localStorage helpers
// ══════════════════════════════════════════════════════════════════════

const LS = {
  get: k      => { try { return localStorage.getItem(k); } catch { return null; } },
  set: (k, v) => { try { localStorage.setItem(k, v);     } catch {} },
  rm:  k      => { try { localStorage.removeItem(k);      } catch {} },
};

function persistRooms() {
  const arr = [...state.rooms.values()].map(r => ({
    pub:           r.pub,
    name:          r.name,
    inviteUri:     r.inviteUri     || null,
    committedJson: r.committedJson || null,
  }));
  LS.set("toloo_rooms", JSON.stringify(arr));
}

function persistRelayUrls() {
  LS.set("toloo_relay_urls", JSON.stringify(state.relayUrls));
}

function saveState() {
  persistRooms();
}

function loadPersistedState() {
  // Multi-relay list (new format). Migrate from old single-URL key if needed.
  const rawUrls = LS.get("toloo_relay_urls");
  if (rawUrls) {
    try { state.relayUrls = JSON.parse(rawUrls); } catch { state.relayUrls = []; }
  } else {
    const oldUrl = LS.get("toloo_relay");
    if (oldUrl) { state.relayUrls = [oldUrl]; persistRelayUrls(); LS.rm("toloo_relay"); }
  }

  const rawRooms = LS.get("toloo_rooms");
  if (rawRooms) {
    try {
      JSON.parse(rawRooms).forEach(r => state.rooms.set(r.pub, {
        pub:           r.pub,
        name:          r.name          || null,
        inviteUri:     r.inviteUri     || null,
        committedJson: r.committedJson || null,
        messages:      [],
        syncAfter:     0,
      }));
    } catch { /* ignore */ }
  }

}


// ══════════════════════════════════════════════════════════════════════
// Jdenticon helpers
// ══════════════════════════════════════════════════════════════════════

function drawJdenticon(svgEl, value) {
  svgEl.setAttribute("data-jdenticon-value", value || "");
  if (value && typeof jdenticon !== "undefined") {
    jdenticon.update(svgEl, value);
  }
}

function makeAvatar(value, sizePx) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("width",  sizePx);
  svg.setAttribute("height", sizePx);
  drawJdenticon(svg, value);
  return svg;
}


// ══════════════════════════════════════════════════════════════════════
// Toast notifications
// ══════════════════════════════════════════════════════════════════════

function toast(msg, type = "info", ms = 3800) {
  const el = document.createElement("div");
  el.className = type !== "info" ? `toast ${type}` : "toast";
  el.textContent = msg;
  $("toast-container").appendChild(el);
  setTimeout(() => el.remove(), ms);
}


// ══════════════════════════════════════════════════════════════════════
// OS notifications (Tauri-native with Web Notifications API fallback)
// ══════════════════════════════════════════════════════════════════════

// Permission is requested lazily on first call and cached here.
let _notifyPermission = null;

async function notify(title, body = "") {
  // ── Tauri native path ──────────────────────────────────────────────
  if (IS_TAURI) {
    const n = window.__TAURI_PLUGIN_NOTIFICATION__;
    if (n) {
      if (_notifyPermission === null) {
        _notifyPermission = await n.isPermissionGranted();
        if (!_notifyPermission) {
          const result = await n.requestPermission();
          _notifyPermission = result === "granted";
        }
      }
      if (_notifyPermission) {
        n.sendNotification({ title, body });
      }
      return;
    }
  }

  // ── Web Notifications API fallback (browser / toloo.min.js) ───────
  if (!("Notification" in window)) return;
  if (_notifyPermission === null) {
    const result = await Notification.requestPermission();
    _notifyPermission = result === "granted";
  }
  if (_notifyPermission) {
    new Notification(title, { body });
  }
}


// ══════════════════════════════════════════════════════════════════════
// DOM shortcuts
// ══════════════════════════════════════════════════════════════════════

const $ = id => document.getElementById(id);

function escapeHtml(s) {
  return s
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// Message delivery status label.
// status field: "sending" | "waiting" | "sent" | "failed"
// depth-2 without status (synced from relay) is always "sent".
function msgStatusLabel(msg) {
  if (msg.status === "failed")  return "✗ Failed";
  if (msg.status === "sending") return "⋯ Pending…";
  if (msg.status === "waiting") return "⏱ Waiting";
  if (msg.depth >= 2)           return "✓ Sent";
  return "⏱ Waiting";
}

function fmtTime(ts) {
  const d = new Date(ts), now = new Date();
  return d.toDateString() === now.toDateString()
    ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    : d.toLocaleDateString([], { month: "short", day: "numeric" });
}

function downloadText(content, filename, mimeType = "text/plain") {
  const blob = new Blob([content], { type: mimeType });
  const a = Object.assign(document.createElement("a"), {
    href:     URL.createObjectURL(blob),
    download: filename,
  });
  a.click();
  URL.revokeObjectURL(a.href);
}


// ══════════════════════════════════════════════════════════════════════
// RTL / direction
// ══════════════════════════════════════════════════════════════════════

const RTL_LANGS = ["fa", "ar", "he", "ur", "ku", "ps", "yi", "dv", "ug"];

function applyDir(dir) {
  document.documentElement.dir = dir;
  LS.set("toloo_dir", dir);
  document.querySelectorAll("[data-dir]").forEach(btn =>
    btn.classList.toggle("active-dir", btn.dataset.dir === dir)
  );
}

function initDir() {
  const saved = LS.get("toloo_dir");
  if (saved) { applyDir(saved); return; }
  const lang = (navigator.language || "en").split("-")[0];
  applyDir(RTL_LANGS.includes(lang) ? "rtl" : "ltr");
}


// ══════════════════════════════════════════════════════════════════════
// Identity
// ══════════════════════════════════════════════════════════════════════

function applyNode(info) {
  state.node = info;

  $("no-id-icon").classList.add("hidden");
  const myAvatar = $("my-avatar");
  myAvatar.classList.remove("hidden");
  drawJdenticon(myAvatar, info.sig_pub);

  $("no-identity-section").classList.add("hidden");
  $("has-identity-section").classList.remove("hidden");
  const ppSection = $("passphrase-section");
  if (ppSection) ppSection.classList.remove("hidden");
  $("my-pubkey").textContent = info.sig_pub;

  const wrap = $("id-avatar-wrap");
  wrap.innerHTML = "";
  wrap.appendChild(makeAvatar(info.sig_pub, 48));
}

function clearNode() {
  state.node = null;
  $("my-avatar").classList.add("hidden");
  $("no-id-icon").classList.remove("hidden");
  $("no-identity-section").classList.remove("hidden");
  $("has-identity-section").classList.add("hidden");
  const ppSection = $("passphrase-section");
  if (ppSection) ppSection.classList.add("hidden");
  LS.rm("toloo_node");
}

async function handleKeygen() {
  try {
    const info = await invoke("keygen");
    applyNode(info);
    LS.set("toloo_node", info.node_json);
    toast("New identity generated.", "success");
  } catch (e) { toast(String(e), "error"); }
}

function handleLoadIdentity() { $("file-input").click(); }

$("file-input").addEventListener("change", async () => {
  const file = $("file-input").files[0];
  if (!file) return;
  const text = await file.text();
  try {
    const info = await invoke("load_node", { nodeJson: text });
    applyNode(info);
    LS.set("toloo_node", text);
    toast("Identity loaded.", "success");
  } catch (e) { toast(String(e), "error"); }
  $("file-input").value = "";
});

function handleSaveIdentity() {
  if (!state.node) return;
  downloadText(state.node.node_json, "toloo-identity.json", "application/json");
}


// ══════════════════════════════════════════════════════════════════════
// Encrypted identity
// ══════════════════════════════════════════════════════════════════════

async function handleEncryptSave() {
  if (!state.node) { toast("Load an identity first.", "error"); return; }
  const passphrase = $("passphrase-input").value;
  if (!passphrase) { toast("Enter a passphrase.", "error"); return; }
  try {
    const blob = await invoke("encrypt_identity", { passphrase });
    downloadText(blob, "toloo-identity.toloo-key");
    LS.set("toloo_encrypted_node", blob);
    $("passphrase-input").value = "";
    toast("Encrypted identity saved.", "success");
  } catch (e) { toast("Encryption failed: " + e, "error"); }
}

async function handleLoadEncrypted() {
  const passphrase = $("passphrase-unlock-input").value;
  if (!passphrase) { toast("Enter a passphrase.", "error"); return; }
  const blob = LS.get("toloo_encrypted_node");
  if (!blob) { toast("No encrypted identity found. Import a .toloo-key file first.", "error"); return; }
  try {
    const info = await invoke("load_encrypted_identity", { encryptedBlob: blob, passphrase });
    applyNode(info);
    LS.set("toloo_node", info.node_json);
    $("passphrase-unlock-input").value = "";
    toast("Identity unlocked.", "success");
  } catch (e) { toast("Wrong passphrase or corrupted data.", "error"); }
}


// ══════════════════════════════════════════════════════════════════════
// Modal / sheet management
// ══════════════════════════════════════════════════════════════════════

function openModal(id) {
  $("overlay").classList.remove("hidden");
  $("overlay").querySelectorAll(".sheet").forEach(s => s.classList.add("hidden"));
  $(id).classList.remove("hidden");
}

function closeModal(id) {
  $(id).classList.add("hidden");
  $("overlay").classList.add("hidden");
}

function bindTabs(container) {
  container.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const target = btn.dataset.tab;
      container.querySelectorAll(".tab-btn").forEach(b => {
        b.classList.toggle("active", b === btn);
        b.setAttribute("aria-selected", String(b === btn));
      });
      container.querySelectorAll(".tab-panel").forEach(p =>
        p.classList.toggle("hidden", p.id !== target)
      );
    });
  });
}


// ══════════════════════════════════════════════════════════════════════
// Relay URL list (client connections in Identity & Settings)
// ══════════════════════════════════════════════════════════════════════

function addRelayUrl(url) {
  url = url.trim();
  if (!url) return;
  if (state.relayUrls.includes(url)) { toast("Already in list.", "info"); return; }
  state.relayUrls.push(url);
  persistRelayUrls();
  renderRelayUrls();
  renderRelayUrlSuggestions();
}

function removeRelayUrl(url) {
  state.relayUrls = state.relayUrls.filter(u => u !== url);
  persistRelayUrls();
  renderRelayUrls();
  renderRelayUrlSuggestions();
}

function renderRelayUrls() {
  const list = $("relay-url-list");
  if (!list) return;
  list.innerHTML = "";

  if (!state.relayUrls.length) {
    const empty = document.createElement("div");
    empty.className = "relay-url-empty";
    empty.textContent = "No relays configured — add one below.";
    list.appendChild(empty);
    return;
  }

  state.relayUrls.forEach(url => {
    const item = document.createElement("div");
    item.className = "relay-url-item";
    item.innerHTML =
      `<span class="relay-url-text">${escapeHtml(url)}</span>` +
      `<button class="relay-url-remove icon-btn" title="Remove">✕</button>`;
    item.querySelector(".relay-url-remove").addEventListener("click", () => removeRelayUrl(url));
    list.appendChild(item);
  });
}

// Show running local ws/wss relays not yet in the connection list as quick-add chips.
function renderRelayUrlSuggestions() {
  const el = $("relay-url-suggestions");
  if (!el) return;

  const suggestions = state.runningRelays
    .filter(r => r.proto === "ws" || r.proto === "wss")
    .map(r => `${r.proto}://${r.host}:${r.port}`)
    .filter(url => !state.relayUrls.includes(url));

  el.innerHTML = "";
  if (!suggestions.length) { el.classList.add("hidden"); return; }
  el.classList.remove("hidden");

  const label = document.createElement("span");
  label.className = "relay-url-suggest-label";
  label.textContent = "Running locally:";
  el.appendChild(label);

  suggestions.forEach(url => {
    const btn = document.createElement("button");
    btn.className = "relay-url-suggest-chip secondary small";
    btn.textContent = `+ ${url}`;
    btn.addEventListener("click", () => addRelayUrl(url));
    el.appendChild(btn);
  });
}


// ══════════════════════════════════════════════════════════════════════
// Blocklist
// ══════════════════════════════════════════════════════════════════════

async function loadBlocklist() {
  if (!IS_TAURI) return;
  try {
    state.blocklist = await invoke("get_blocklist_cmd");
  } catch { state.blocklist = []; }
}

function isBlocked(nodePub) {
  return state.blocklist.some(b => b.node_pub === nodePub);
}

function renderBlocklist() {
  const list  = $("blocklist-list");
  const empty = $("blocklist-empty");
  if (!list) return;
  list.innerHTML = "";

  if (!state.blocklist.length) {
    if (empty) empty.classList.remove("hidden");
    return;
  }
  if (empty) empty.classList.add("hidden");

  state.blocklist.forEach(entry => {
    const item = document.createElement("div");
    item.className = "blocklist-item";

    const avWrap = document.createElement("div");
    avWrap.className = "blocklist-avatar";
    avWrap.appendChild(makeAvatar(entry.node_pub, 28));

    const info = document.createElement("div");
    info.className = "blocklist-info";
    info.innerHTML =
      `<div class="blocklist-node">${escapeHtml(entry.node_pub)}</div>` +
      (entry.reason ? `<div class="blocklist-reason">${escapeHtml(entry.reason)}</div>` : "");

    const btn = document.createElement("button");
    btn.className = "blocklist-unblock secondary small";
    btn.textContent = "Unblock";
    btn.addEventListener("click", () => handleUnblockNode(entry.node_pub));

    item.append(avWrap, info, btn);
    list.appendChild(item);
  });
}

async function handleBlockNode(nodePub) {
  if (!IS_TAURI) return;
  const reason = prompt("Reason for blocking (optional):");
  try {
    await invoke("block_node_cmd", { nodePub, reason: reason || null });
    await loadBlocklist();
    renderBlocklist();
    renderMessages();
    toast("User blocked.", "success");
  } catch (e) { toast("Block failed: " + e, "error"); }
}

async function handleUnblockNode(nodePub) {
  if (!IS_TAURI) return;
  try {
    await invoke("unblock_node_cmd", { nodePub });
    await loadBlocklist();
    renderBlocklist();
    renderMessages();
    toast("User unblocked.", "success");
  } catch (e) { toast("Unblock failed: " + e, "error"); }
}

// ══════════════════════════════════════════════════════════════════════
// Room management
// ══════════════════════════════════════════════════════════════════════

function roomLabel(room) {
  return room.name || room.pub.slice(0, 8) + "…";
}

function upsertRoom(pub, { name = null, inviteUri = null, committedJson = null } = {}, select = true) {
  if (!state.rooms.has(pub)) {
    state.rooms.set(pub, {
      pub, name, inviteUri, committedJson,
      messages: [], syncAfter: 0,
    });
  } else {
    const r = state.rooms.get(pub);
    if (name)          r.name          = name;
    if (inviteUri)     r.inviteUri     = inviteUri;
    if (committedJson) r.committedJson = committedJson;
  }
  persistRooms();
  renderRoomsList();
  if (select) selectRoom(pub);
}

function selectRoom(pub) {
  state.activeRoom = pub;
  renderRoomsList();
  renderChatView();
  document.getElementById("app").classList.add("chat-open");
}

function renderRoomsList() {
  const list  = $("rooms-list");
  const hint  = $("no-rooms-hint");
  const query = $("search-input").value.trim().toLowerCase();
  let   rooms = [...state.rooms.values()];

  if (query) {
    rooms = rooms.filter(r =>
      roomLabel(r).toLowerCase().includes(query) ||
      r.pub.toLowerCase().includes(query)
    );
  }

  if (rooms.length === 0) {
    list.innerHTML = "";
    hint.style.display = "block";
    hint.innerHTML = query
      ? "No rooms match your search."
      : "Add a room with the <strong>+</strong> button above.";
    return;
  }

  hint.style.display = "none";
  list.innerHTML = "";

  rooms.forEach(room => {
    const isActive = state.activeRoom === room.pub;
    const last     = room.messages.at(-1);

    const item = document.createElement("div");
    item.className = "room-item" + (isActive ? " active" : "");
    item.setAttribute("role", "listitem");

    const avWrap = document.createElement("div");
    avWrap.className = "room-avatar";
    avWrap.appendChild(makeAvatar(room.pub, 44));

    const info = document.createElement("div");
    info.className = "room-info";
    info.innerHTML = `
      <div class="room-name">${escapeHtml(roomLabel(room))}</div>
      <div class="room-preview">${last
        ? escapeHtml(last.body.slice(0, 60))
        : escapeHtml(room.pub.slice(0, 20)) + "…"
      }</div>
    `;

    const meta = document.createElement("div");
    meta.className = "room-meta";
    if (last) meta.innerHTML = `<div class="room-time">${fmtTime(last.ts)}</div>`;

    item.append(avWrap, info, meta);
    item.addEventListener("click", () => selectRoom(room.pub));
    attachCtxTrigger(item, () => roomCtxItems(room));
    list.appendChild(item);
  });
}


// ══════════════════════════════════════════════════════════════════════
// Chat view
// ══════════════════════════════════════════════════════════════════════

function renderChatView() {
  const room = state.activeRoom ? state.rooms.get(state.activeRoom) : null;

  if (!room) {
    $("welcome").classList.remove("hidden");
    $("chat-view").classList.add("hidden");
    return;
  }

  $("welcome").classList.add("hidden");
  $("chat-view").classList.remove("hidden");

  const avWrap = $("chat-avatar-wrap");
  avWrap.innerHTML = "";
  avWrap.appendChild(makeAvatar(room.pub, 36));
  $("chat-name").textContent = roomLabel(room);
  $("chat-key").textContent  = room.pub;

  renderMessages();
}

function renderMessages() {
  const room = state.activeRoom ? state.rooms.get(state.activeRoom) : null;
  if (!room) return;

  const list = $("messages-list");
  list.innerHTML = "";

  room.messages.forEach(msg => {
    if (isBlocked(msg.author)) return;
    const isOwn = state.node && msg.author === state.node.sig_pub;

    const group = document.createElement("div");
    group.className = "msg-group" + (isOwn ? " own" : "");

    const avEl = document.createElement("div");
    avEl.className = "msg-avatar";
    avEl.appendChild(makeAvatar(msg.author, 26));

    const bubbles = document.createElement("div");
    bubbles.className = "msg-bubbles";

    if (!isOwn) {
      const authorEl = document.createElement("div");
      authorEl.className = "msg-author";
      authorEl.textContent = msg.author.slice(0, 8) + "…";
      bubbles.appendChild(authorEl);
    }

    const bubble = document.createElement("div");
    bubble.className = "msg-bubble";
    bubble.textContent = msg.body;
    attachCtxTrigger(bubble, () => msgCtxItems(msg, room));
    bubbles.appendChild(bubble);

    const metaEl = document.createElement("div");
    metaEl.className = "msg-meta";
    const statusLabel = msgStatusLabel(msg);
    metaEl.textContent = `${fmtTime(msg.ts)} · ${statusLabel}`;
    bubbles.appendChild(metaEl);

    group.append(avEl, bubbles);
    list.appendChild(group);
  });

  list.scrollTop = list.scrollHeight;
}

function appendSystemMsg(text) {
  const list = $("messages-list");
  if (!list) return;
  const el = document.createElement("div");
  el.className = "system-msg";
  el.textContent = text;
  list.appendChild(el);
  list.scrollTop = list.scrollHeight;
}


// ══════════════════════════════════════════════════════════════════════
// Sync
// ══════════════════════════════════════════════════════════════════════

async function handleSync() {
  const room = state.activeRoom ? state.rooms.get(state.activeRoom) : null;
  if (!room)                   { toast("Select a room first.", "error"); return; }
  if (!state.relayUrls.length) { toast("Add a relay in Identity & Settings.", "error"); return; }

  appendSystemMsg("Syncing…");

  // Query all relays in parallel and merge results.
  const results = await Promise.allSettled(
    state.relayUrls.map(url =>
      invoke("fetch_messages", { relayUrl: url, roomPub: room.pub, after: room.syncAfter })
    )
  );

  let added = 0, reached = 0;
  results.forEach(r => {
    if (r.status !== "fulfilled") return;
    reached++;
    r.value.forEach(msg => {
      const existing = room.messages.find(m => m.eid === msg.eid);
      if (!existing) {
        // New message from relay — if it's depth-2 and we authored it, mark sent.
        if (msg.depth >= 2 && state.node && msg.author === state.node.sig_pub)
          msg.status = "sent";
        room.messages.push(msg);
        added++;
      } else if (msg.depth > existing.depth) {
        // Relay has a deeper version (e.g. depth-2 for a message we sent as depth-1).
        existing.depth = msg.depth;
        existing.envelope_json = msg.envelope_json;
        if (msg.depth >= 2) existing.status = "sent";
      }
    });
    if (r.value.length)
      room.syncAfter = Math.max(room.syncAfter, ...r.value.map(m => m.ts));
  });

  // Drop pending messages that have been committed (matched by author+body).
  room.messages = room.messages.filter(m => {
    if (!m.eid.startsWith("pending-")) return true;
    return !room.messages.some(r =>
      !r.eid.startsWith("pending-") && r.author === m.author && r.body === m.body
    );
  });

  // Deduplicate by eid keeping highest depth; pending-* entries are superseded by real eids.
  const byEid = new Map();
  room.messages.forEach(m => {
    const prev = byEid.get(m.eid);
    if (!prev || m.depth > prev.depth) byEid.set(m.eid, m);
  });
  room.messages = [...byEid.values()];

  room.messages.sort((a, b) => a.ts - b.ts);
  renderMessages();
  renderRoomsList();

  if (!reached) {
    appendSystemMsg("All relays unreachable.");
    toast("Sync failed.", "error");
  } else {
    appendSystemMsg(added ? `Synced ${added} message(s) via ${reached} relay(s).` : "Already up to date.");
  }
}


// ══════════════════════════════════════════════════════════════════════
// Send message
// ══════════════════════════════════════════════════════════════════════

async function handleSend(e) {
  e.preventDefault();
  const body = $("compose-input").value.trim();
  if (!body) return;

  const room = state.activeRoom ? state.rooms.get(state.activeRoom) : null;
  if (!room)       { toast("Select a room first.", "error"); return; }
  if (!state.node) { toast("Load an identity first.", "error"); return; }
  if (!state.relayUrls.length) { toast("Add a relay in Identity & Settings.", "error"); return; }

  try {
    const envJson = await invoke("sign_message", {
      roomPub: room.pub,
      channel: 0,
      body,
    });

    const pendingEid = `pending-${Date.now()}`;
    const MSG_TTL_MS = 5 * 60 * 1000; // 5 minutes
    room.messages.push({
      eid:           pendingEid,
      author:        state.node.sig_pub,
      body,
      ts:            Date.now(),
      sentAt:        Date.now(),
      depth:         1,
      status:        "sending",  // "sending" | "waiting" | "sent" | "failed"
      envelope_json: envJson,
    });
    renderMessages();
    renderRoomsList();
    $("compose-input").value = "";

    // Build the offer: always include the room.create envelope so the relay has
    // the room metadata it needs to validate and auto-commit, even if it just started.
    const offer = room.committedJson ? [room.committedJson, envJson] : [envJson];

    // Broadcast to all relays.
    const results = await Promise.allSettled(
      state.relayUrls.map(url =>
        invoke("pool_exchange", { relayUrl: url, offer, wantRooms: [room.pub], after: 0 })
      )
    );

    const allFailed = results.every(r => r.status === "rejected");
    if (allFailed) {
      // No relay reachable — mark as failed immediately.
      const pending = room.messages.find(m => m.eid === pendingEid);
      if (pending) pending.status = "failed";
      renderMessages();
      toast("Could not reach any relay.", "warn");
      return;
    }

    // At least one relay accepted depth-1 → "waiting" for commit.
    const pending = room.messages.find(m => m.eid === pendingEid);
    if (pending) pending.status = "waiting";
    renderMessages();

    // Collect any depth-2 commits returned in the same response (key-holder relay case).
    const committed = [];
    results.forEach(r => {
      if (r.status !== "fulfilled") return;
      r.value.forEach(ej => {
        try {
          const env   = JSON.parse(ej);
          const inner = env?.d?.env?.d ?? env?.d;
          if (inner?.t !== "room.message" || inner?.r !== room.pub) return;
          const d = (env.d.t === "commit" || env.d.tc != null) ? 2 : 1;
          if (d < 2) return;
          const ch  = inner?.c?.ch ?? 0;
          const eid = `${ch}:${inner.ts}:${inner.n}`;
          if (!committed.find(m => m.eid === eid))
            committed.push({ eid, author: inner.n, body: inner?.c?.body || "",
                             ts: inner.ts, depth: d, status: "sent", envelope_json: ej });
        } catch { /* ignore */ }
      });
    });

    if (committed.length) {
      // Drop the pending placeholder and insert committed versions.
      room.messages = room.messages.filter(m => {
        if (!m.eid.startsWith("pending-")) return true;
        return !committed.some(c => c.author === m.author && c.body === m.body);
      });
      committed.forEach(c => {
        if (!room.messages.find(m => m.eid === c.eid)) room.messages.push(c);
      });
      room.messages.sort((a, b) => a.ts - b.ts);
      renderMessages();

      // Depth-3 ack: wrap the commit and broadcast so relays stop forwarding (spec §6.2.3).
      // This is a network efficiency signal — UI stays "✓ Sent" at depth-2.
      if (IS_TAURI) {
        const myCommits = committed.filter(c => c.author === state.node.sig_pub);
        for (const c of myCommits) {
          try {
            const ackJson = await invoke("ack_commit", { committedJson: c.envelope_json });
            state.relayUrls.forEach(url =>
              invoke("pool_exchange", { relayUrl: url, offer: [ackJson], wantRooms: [], after: 0 })
                .catch(() => {})
            );
          } catch { /* ack is optional */ }
        }
      }
    } else {
      // No commit in this response — schedule expiry check.
      setTimeout(() => {
        const m = room.messages.find(m => m.eid === pendingEid);
        if (m && m.status === "waiting" && (Date.now() - m.sentAt) >= MSG_TTL_MS)
          { m.status = "failed"; renderMessages(); }
      }, MSG_TTL_MS);
    }
  } catch (e) {
    toast("Send failed: " + e, "error");
  }
}


// ══════════════════════════════════════════════════════════════════════
// Create room
// ══════════════════════════════════════════════════════════════════════

async function handleCreateRoom() {
  if (!state.node) { toast("Load an identity first.", "error"); return; }
  const name = $("new-room-name").value.trim() || null;
  try {
    // Returns [room_pub, committed_json, invite_uri]
    const [roomPub, committedJson, inviteUri] = await invoke("create_room", {
      name,
      rulesJson: JSON.stringify([
        { t: "join", allow: "*" },
        { t: "post", allow: "*" },
      ]),
    });

    // Publish room.create to all relays (best-effort broadcast).
    state.relayUrls.forEach(url =>
      invoke("pool_exchange", { relayUrl: url, offer: [committedJson], wantRooms: [], after: 0 })
        .catch(() => {})
    );

    upsertRoom(roomPub, { name, inviteUri, committedJson }, true);
    closeModal("add-room-modal");
    $("new-room-name").value = "";
    toast("Room created.", "success");
  } catch (e) { toast(String(e), "error"); }
}


// ══════════════════════════════════════════════════════════════════════
// Join room (by raw pub key)
// ══════════════════════════════════════════════════════════════════════

async function handleJoinRoom() {
  if (!state.node) { toast("Load an identity first.", "error"); return; }
  const roomPub = $("join-room-pub").value.trim();
  const name    = $("join-room-name").value.trim() || null;
  if (!roomPub)  { toast("Enter a room public key.", "error"); return; }

  try {
    const envJson = await invoke("join_room", { roomPub });

    // Submit join to first reachable relay; broadcast offer to rest.
    for (const url of state.relayUrls) {
      try {
        await invoke("pool_exchange", { relayUrl: url, offer: [envJson], wantRooms: [roomPub], after: 0 });
        break;
      } catch { /* try next */ }
    }

    upsertRoom(roomPub, { name }, true);
    closeModal("add-room-modal");
    $("join-room-pub").value  = "";
    $("join-room-name").value = "";
    toast("Joined room.", "success");
  } catch (e) { toast(String(e), "error"); }
}


// ══════════════════════════════════════════════════════════════════════
// Universal import (toloo:// URI or .toloo file — any content type)
// ══════════════════════════════════════════════════════════════════════

// Last classified result, held until user confirms or clears.
let _importClassified = null;

/**
 * Classify decoded envelopes by event type.
 * Returns { rooms, messages, relayEndpoints, unknown }.
 *
 * relayEndpoints: Array of { url, proto } — ALL protos, not just ws/wss.
 * The display layer annotates them; applyImport only wires up connectable ones.
 */
function classifyEnvelopes(envJsons) {
  const rooms    = new Map(); // pub → { pub, name, creator, envJson }
  const messages = [];
  const relayEndpointsMap = new Map(); // url → { url, proto }
  let unknown = 0;

  for (const j of envJsons) {
    try {
      const env   = JSON.parse(j);
      const inner = env?.d?.env?.d ?? env?.d;
      const t     = inner?.t;

      if (t === "room.create") {
        // Committed: outer d.n = room pub (room is signer of commit).
        // Raw depth-1: inner.r = room pub.
        const roomPub = (env.d.t === "commit") ? env.d.n : inner.r;
        if (roomPub && !rooms.has(roomPub)) {
          rooms.set(roomPub, {
            pub:     roomPub,
            name:    inner?.c?.name || null,
            creator: inner.n,
            envJson: j,
          });
        }

      } else if (t === "room.message") {
        const roomPub = inner.r;
        if (!roomPub) { unknown++; continue; }
        const ch  = inner?.c?.ch ?? 0;
        const eid = `${ch}:${inner.ts}:${inner.n}`;
        messages.push({
          eid, roomPub,
          author:  inner.n,
          body:    inner?.c?.body || "",
          ts:      inner.ts,
          depth:   env.d.t === "commit" ? 2 : 1,
          envJson: j,
        });

      } else if (t === "node.meta") {
        // Collect ALL endpoint protos — display layer annotates each one.
        const endpoints = inner?.c?.endpoints ?? [];
        endpoints.forEach(ep => {
          if (!ep.proto || !ep.host) return;
          const path   = ep.path && ep.path !== "/" ? ep.path : "";
          const skin   = ep.skin && ep.key ? `?skin=${ep.skin}&key=${ep.key}` : "";
          const url    = `${ep.proto}://${ep.host}:${ep.port}${path}${skin}`;
          if (!relayEndpointsMap.has(url)) {
            relayEndpointsMap.set(url, { url, proto: ep.proto });
          }
        });

      } else {
        unknown++;
      }
    } catch { unknown++; }
  }

  return {
    rooms:          [...rooms.values()],
    messages,
    relayEndpoints: [...relayEndpointsMap.values()],
    unknown,
  };
}

/**
 * Decode raw input (toloo:// or .toloo text) then show categorised preview.
 */
async function importAll(raw) {
  raw = raw.trim();
  if (!raw) { toast("Paste a link or open a file first.", "error"); return; }
  try {
    const envJsons = await invoke("decode", { input: raw });
    if (!envJsons.length) { toast("No valid envelopes found in input.", "error"); return; }
    _importClassified = classifyEnvelopes(envJsons);
    showImportResults(_importClassified);
  } catch (e) { toast("Could not decode input: " + e, "error"); }
}

/**
 * Render the import preview inside #import-results.
 */
function showImportResults(c) {
  const resultsEl = $("import-results");
  const listEl    = $("import-results-list");
  if (!resultsEl || !listEl) return;
  listEl.innerHTML = "";

  const total = c.rooms.length + c.messages.length + c.relayEndpoints.length;
  if (!total && !c.unknown) {
    listEl.innerHTML = `<p class="hint-text" style="padding:8px 16px 4px">Nothing recognized in input.</p>`;
    resultsEl.classList.remove("hidden");
    return;
  }

  if (c.rooms.length) {
    const section = document.createElement("div");
    section.className = "import-section";
    section.innerHTML = `<div class="import-section-title">Rooms (${c.rooms.length})</div>`;
    c.rooms.forEach(r => {
      const row = document.createElement("div");
      row.className = "import-row";
      row.innerHTML =
        `<span class="import-row-label">${escapeHtml(r.name || "(unnamed)")}</span>` +
        `<span class="import-row-sub monospace">${escapeHtml(r.pub.slice(0, 12))}…</span>`;
      section.appendChild(row);
    });
    listEl.appendChild(section);
  }

  if (c.messages.length) {
    // Group by room pub.
    const byRoom = new Map();
    c.messages.forEach(m => byRoom.set(m.roomPub, (byRoom.get(m.roomPub) || 0) + 1));

    const section = document.createElement("div");
    section.className = "import-section";
    section.innerHTML = `<div class="import-section-title">Messages (${c.messages.length})</div>`;
    byRoom.forEach((count, roomPub) => {
      const known = state.rooms.get(roomPub);
      const label = known ? (known.name || roomPub.slice(0, 12) + "…") : roomPub.slice(0, 12) + "…";
      const row = document.createElement("div");
      row.className = "import-row";
      row.innerHTML =
        `<span class="import-row-label">${escapeHtml(label)}</span>` +
        `<span class="import-row-sub">${count} message${count !== 1 ? "s" : ""}</span>`;
      section.appendChild(row);
    });
    listEl.appendChild(section);
  }

  if (c.relayEndpoints.length) {
    const section = document.createElement("div");
    section.className = "import-section";
    section.innerHTML = `<div class="import-section-title">Relay Endpoints (${c.relayEndpoints.length})</div>`;
    c.relayEndpoints.forEach(ep => {
      // In native mode, the Rust backend handles all protos.
      // In browser-only mode, only ws/wss work (no TCP/HTTP client).
      const connectable  = IS_TAURI || ep.proto === "ws" || ep.proto === "wss";
      const alreadyAdded = state.relayUrls.includes(ep.url);
      const row = document.createElement("div");
      row.className = "import-row";
      const sub = alreadyAdded  ? "✓ already connected"
                : !connectable  ? `${ep.proto} — browser only supports ws/wss`
                : "";
      row.innerHTML =
        `<span class="import-row-label monospace">${escapeHtml(ep.url)}</span>` +
        (sub ? `<span class="import-row-sub">${escapeHtml(sub)}</span>` : "");
      section.appendChild(row);
    });
    listEl.appendChild(section);
  }

  if (c.unknown) {
    const note = document.createElement("div");
    note.className = "import-unknown";
    note.textContent = `${c.unknown} unrecognized envelope${c.unknown !== 1 ? "s" : ""} skipped.`;
    listEl.appendChild(note);
  }

  resultsEl.classList.remove("hidden");
}

/**
 * Apply all classified import data to state.
 */
async function applyImport() {
  const c = _importClassified;
  if (!c) return;

  let addedRooms = 0, addedMsgs = 0, addedRelays = 0;
  let firstNewRoom = null;

  // 1. Rooms — join and announce to relays.
  for (const room of c.rooms) {
    if (state.rooms.has(room.pub)) continue;
    try {
      if (state.node) {
        const envJson = await invoke("join_room", { roomPub: room.pub });
        for (const url of state.relayUrls) {
          try {
            await invoke("pool_exchange", {
              relayUrl: url, offer: [envJson],
              wantRooms: [room.pub], after: 0,
            });
            break;
          } catch { /* try next relay */ }
        }
      }
      upsertRoom(room.pub, { name: room.name }, false);
      if (!firstNewRoom) firstNewRoom = room.pub;
      addedRooms++;
    } catch { /* skip */ }
  }

  // 2. Messages — group into existing or stub rooms.
  const affectedRooms = new Set();
  for (const msg of c.messages) {
    if (!state.rooms.has(msg.roomPub)) upsertRoom(msg.roomPub, {}, false);
    const room = state.rooms.get(msg.roomPub);
    if (room.messages.find(m => m.eid === msg.eid)) continue;
    room.messages.push({
      eid:           msg.eid,
      author:        msg.author,
      body:          msg.body,
      ts:            msg.ts,
      depth:         msg.depth,
      envelope_json: msg.envJson,
    });
    addedMsgs++;
    affectedRooms.add(msg.roomPub);
  }
  affectedRooms.forEach(pub => {
    const room = state.rooms.get(pub);
    if (room) room.messages.sort((a, b) => a.ts - b.ts);
  });

  // 3. Relay endpoints.
  // Native mode: Rust backend handles ws/wss/http/https/tcp — add them all.
  // Browser mode: only ws/wss are connectable via JS WebSocket.
  let skippedRelays = 0;
  for (const ep of c.relayEndpoints) {
    const connectable = IS_TAURI || ep.proto === "ws" || ep.proto === "wss";
    if (!connectable) { skippedRelays++; continue; }
    if (!state.relayUrls.includes(ep.url)) {
      state.relayUrls.push(ep.url);
      addedRelays++;
    }
  }
  if (addedRelays) persistRelayUrls();

  // Re-render.
  persistRooms();
  renderRoomsList();
  if (firstNewRoom) selectRoom(firstNewRoom);
  else renderChatView();

  // Done — clear modal and notify.
  clearImportModal();
  closeModal("import-modal");

  const parts = [];
  if (addedRooms)  parts.push(`${addedRooms} room${addedRooms !== 1 ? "s" : ""}`);
  if (addedMsgs)   parts.push(`${addedMsgs} message${addedMsgs !== 1 ? "s" : ""}`);
  if (addedRelays) parts.push(`${addedRelays} relay${addedRelays !== 1 ? "s" : ""}`);

  if (parts.length) {
    toast(`Imported: ${parts.join(", ")}.`, "success");
  } else {
    // Build a useful "already up to date" message.
    const alreadyConnected = c.relayEndpoints.filter(ep =>
      (ep.proto === "ws" || ep.proto === "wss") && state.relayUrls.includes(ep.url)
    ).length;
    const notConnectable = c.relayEndpoints.filter(ep =>
      ep.proto !== "ws" && ep.proto !== "wss"
    ).length;
    if (alreadyConnected > 0) {
      toast(`Already connected to ${alreadyConnected} relay${alreadyConnected !== 1 ? "s" : ""}.`, "info");
    } else if (notConnectable > 0) {
      toast(`${notConnectable} endpoint${notConnectable !== 1 ? "s" : ""} found but not connectable in browser mode (only ws/wss supported).`, "info");
    } else {
      toast("Nothing new to import.", "info");
    }
  }
}

function clearImportModal() {
  _importClassified = null;
  const textEl = $("import-text-input");
  if (textEl) { textEl.value = ""; textEl.placeholder = "toloo://BASE64URL…"; }
  const resultsEl = $("import-results");
  if (resultsEl) resultsEl.classList.add("hidden");
  const listEl = $("import-results-list");
  if (listEl) listEl.innerHTML = "";
  $("toloo-file-input").value = "";
}


// ══════════════════════════════════════════════════════════════════════
// Share room invite
// ══════════════════════════════════════════════════════════════════════

async function handleShareRoom() {
  const room = state.activeRoom ? state.rooms.get(state.activeRoom) : null;
  if (!room) return;

  let uri = room.inviteUri;

  // If we don't have the invite URI yet (room was joined, not created here),
  // encode the room pub as a minimal toloo:// URI.
  // In a future version, we'd fetch the room.create from the relay.
  if (!uri && room.committedJson) {
    try {
      uri = await invoke("encode_uri", { envelopeJsons: [room.committedJson] });
      room.inviteUri = uri;
      persistRooms();
    } catch { /* ignore */ }
  }

  if (!uri) {
    toast("No invite URI — share the room public key manually:\n" + room.pub, "info", 6000);
    return;
  }

  $("share-uri-display").value = uri;
  openModal("share-modal");
}

async function handleCopyUri() {
  const uri = $("share-uri-display").value;
  try {
    await navigator.clipboard.writeText(uri);
    toast("Copied to clipboard.", "success");
  } catch {
    // Fallback: select all so the user can copy manually.
    $("share-uri-display").select();
    toast("Select all and copy (Ctrl+C).", "info");
  }
}

async function handleSaveToloo() {
  const room = state.activeRoom ? state.rooms.get(state.activeRoom) : null;
  if (!room) return;

  // Collect all message envelopes + the room invite if available.
  const envJsons = room.messages
    .filter(m => m.envelope_json && !m.eid.startsWith("pending-"))
    .map(m => m.envelope_json);

  if (room.committedJson) envJsons.unshift(room.committedJson);

  if (!envJsons.length) { toast("No messages to export yet.", "info"); return; }

  try {
    const content = await invoke("encode_file", { envelopeJsons: envJsons });
    const label   = roomLabel(room).replace(/[^a-zA-Z0-9_-]/g, "_");
    downloadText(content, `toloo-${label}.toloo`);
    toast(`Exported ${envJsons.length} envelope(s).`, "success");
  } catch (e) { toast("Export failed: " + e, "error"); }
}

async function handleExportMessages() {
  await handleSaveToloo();
}


// ══════════════════════════════════════════════════════════════════════
// Flag messages
// ══════════════════════════════════════════════════════════════════════

async function handleFlagMessage(msg, room) {
  if (!IS_TAURI || !state.node) { toast("Load an identity first.", "error"); return; }
  const category = prompt("Flag category (spam, abuse, off-topic):", "spam");
  if (!category) return;
  const reason = prompt("Reason (optional):");
  try {
    const envJson = await invoke("create_flag", {
      roomPub: room.pub, targetEid: msg.eid, category, reason: reason || null,
    });
    // Broadcast flag to all relays.
    state.relayUrls.forEach(url =>
      invoke("pool_exchange", { relayUrl: url, offer: [envJson], wantRooms: [], after: 0 })
        .catch(() => {})
    );
    toast("Message flagged.", "success");
  } catch (e) { toast("Flag failed: " + e, "error"); }
}


// ══════════════════════════════════════════════════════════════════════
// Attestations
// ══════════════════════════════════════════════════════════════════════

async function handleAttest(nodePub, level) {
  if (!IS_TAURI || !state.node) { toast("Load an identity first.", "error"); return; }
  if (nodePub === state.node.sig_pub) { toast("Cannot attest yourself.", "error"); return; }
  const reason = prompt(`Reason for ${level} attestation (optional):`);
  try {
    const envJson = await invoke("create_attestation", {
      targetNode: nodePub, level, reason: reason || null,
    });
    // Broadcast to all relays.
    state.relayUrls.forEach(url =>
      invoke("pool_exchange", { relayUrl: url, offer: [envJson], wantRooms: [], after: 0 })
        .catch(() => {})
    );
    toast(`${level.charAt(0).toUpperCase() + level.slice(1)} attestation sent.`, "success");
  } catch (e) { toast("Attestation failed: " + e, "error"); }
}


// ══════════════════════════════════════════════════════════════════════
// Local relay management
// ══════════════════════════════════════════════════════════════════════

function fmtBytes(n) {
  if (n < 1024)        return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}

function getRunningInfo(configId) {
  return state.runningRelays.find(r => r.config_id === configId) || null;
}

function renderNetFooter() {
  const el = $("net-summary");
  const running = state.runningRelays;
  const hasRelayUrls = state.relayUrls.length > 0;
  const dotClass = running.length ? "online" : (hasRelayUrls ? "online" : "offline");

  if (!running.length) {
    el.innerHTML =
      `<span class="net-status-dot ${dotClass}"></span>` +
      `${state.savedRelays.length ? state.savedRelays.length + " relay(s) offline" : "No relays configured"}`;
    return;
  }
  const totalActive = running.reduce((s, r) => s + r.active, 0);
  const totalIn     = running.reduce((s, r) => s + r.bytes_in,  0);
  const totalOut    = running.reduce((s, r) => s + r.bytes_out, 0);
  el.innerHTML =
    `<span class="net-status-dot online"></span>` +
    `<span class="net-active">${running.length} relay${running.length > 1 ? "s" : ""}</span>` +
    ` · ${totalActive} peer${totalActive !== 1 ? "s" : ""}` +
    ` <span class="net-bytes">↑${fmtBytes(totalOut)} ↓${fmtBytes(totalIn)}</span>`;
}

function renderRelayList() {
  const list  = $("relay-config-list");
  const empty = $("relay-list-empty");
  list.innerHTML = "";

  if (!state.savedRelays.length) {
    empty.classList.remove("hidden");
    return;
  }
  empty.classList.add("hidden");

  state.savedRelays.forEach(cfg => {
    const info    = getRunningInfo(cfg.id);
    const running = !!info;
    const title   = cfg.skin
      ? `${cfg.proto}+${cfg.skin}://${cfg.host}:${cfg.port}`
      : `${cfg.proto}://${cfg.host}:${cfg.port}`;

    const card = document.createElement("div");
    card.className = "relay-config-card";
    card.dataset.configId = cfg.id;

    card.innerHTML = `
      <div class="relay-card-header">
        <span class="relay-status-dot ${running ? "running" : "stopped"}"></span>
        <span class="relay-card-title">${escapeHtml(title)}</span>
        <div class="relay-card-actions">
          ${running
            ? `<button class="relay-stop-btn danger">Stop</button>`
            : `<button class="relay-start-btn">Start</button>`}
          <button class="relay-delete-btn icon-btn" title="Delete relay">✕</button>
        </div>
      </div>
      ${running && info ? `
        <div class="relay-metrics">
          <div class="relay-metric">
            <span class="relay-metric-label">Peers</span>
            <span class="relay-metric-value hi">${info.active}</span>
          </div>
          <div class="relay-metric">
            <span class="relay-metric-label">Total</span>
            <span class="relay-metric-value">${info.total}</span>
          </div>
          <div class="relay-metric">
            <span class="relay-metric-label">↑ Out</span>
            <span class="relay-metric-value">${fmtBytes(info.bytes_out)}</span>
          </div>
          <div class="relay-metric">
            <span class="relay-metric-label">↓ In</span>
            <span class="relay-metric-value">${fmtBytes(info.bytes_in)}</span>
          </div>
        </div>
        <div class="relay-invite-row">
          <span class="relay-invite-preview">${escapeHtml(info.invite_uri.slice(0, 60))}…</span>
          <button class="relay-copy-btn secondary">Copy invite</button>
        </div>` : ""}
    `;

    if (running) {
      card.querySelector(".relay-stop-btn").addEventListener("click",   () => handleRelayStop(cfg.id));
      card.querySelector(".relay-copy-btn")?.addEventListener("click",  () => copyRelayInvite(info));
    } else {
      card.querySelector(".relay-start-btn").addEventListener("click",  () => handleRelayStart(cfg.id));
    }
    card.querySelector(".relay-delete-btn").addEventListener("click", () => handleRelayDelete(cfg.id));
    list.appendChild(card);
  });
}

// ── Form dynamics ──────────────────────────────

function updateRelayForm() {
  const proto   = $("relay-proto").value;
  const skin    = $("relay-skin").value;
  // obfs4 has built-in encryption; all other protos support optional app-layer skin.
  const hasSkin  = proto !== "obfs4";
  // Protos where a URL path makes sense.
  const hasPath  = ["ws", "wss", "http", "https", "meek"].includes(proto);
  // obfs4-specific fields.
  const hasObfs4 = proto === "obfs4";
  // meek-specific fields.
  const hasMeek  = proto === "meek";

  $("relay-field-skin").classList.toggle("hidden", !hasSkin);
  $("relay-field-padding").classList.toggle("hidden", !(hasSkin && skin));
  $("relay-field-path").classList.toggle("hidden", !hasPath);
  $("relay-field-cert").classList.toggle("hidden", !hasObfs4);
  $("relay-field-iat").classList.toggle("hidden", !hasObfs4);
  $("relay-field-front").classList.toggle("hidden", !hasMeek);
}

function showRelayForm() {
  $("relay-form-panel").classList.remove("hidden");
  $("btn-relay-add").classList.add("hidden");
  if (IS_TAURI) {
    invoke("detect_lan_ip_cmd").then(ip => { $("relay-host").value = ip; }).catch(() => {});
  }
  updateRelayForm();
}

function hideRelayForm() {
  $("relay-form-panel").classList.add("hidden");
  $("btn-relay-add").classList.remove("hidden");
}

async function handleRelaySave() {
  const proto   = $("relay-proto").value;
  const host    = $("relay-host").value.trim() || "127.0.0.1";
  const port    = parseInt($("relay-port").value, 10) || 17701;

  if (port < 1024) {
    toast("Ports below 1024 require root/admin privileges. Use 1024–65535.", "error");
    return;
  }
  const skin    = $("relay-field-skin").classList.contains("hidden")
                ? null : ($("relay-skin").value || null);
  const padding = skin ? ($("relay-padding").value || "none") : null;
  const path    = $("relay-field-path").classList.contains("hidden")
                ? null : ($("relay-path").value.trim() || null);
  const direct  = $("relay-direct").checked;

  const id = typeof crypto.randomUUID === "function"
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(36).slice(2)}`;

  try {
    const record = await invoke("relay_save_config", {
      id, proto, host, port, skin, padding, path, direct,
    });
    state.savedRelays.push(record);
    renderRelayList();
    renderNetFooter();
    hideRelayForm();

    // Reset form to defaults.
    $("relay-proto").value = "ws";
    $("relay-skin").value  = "";
    $("relay-port").value  = "17701";
    $("relay-host").value  = "";
    updateRelayForm();
  } catch (e) { toast("Save failed: " + e, "error"); }
}

// ── Start / Stop / Delete ──────────────────────

async function handleRelayStart(configId) {
  const cfg = state.savedRelays.find(r => r.id === configId);
  if (!cfg) return;
  try {
    const info = await invoke("relay_start", { configId });
    state.runningRelays.push(info);
    renderRelayList();
    renderNetFooter();
    startRelayPolling();
    // Auto-add ws/wss relays to the connected-relay list so the user can
    // immediately start syncing/sending without any manual setup.
    if (cfg.proto === "ws" || cfg.proto === "wss") {
      const relayUrl = `${cfg.proto}://${cfg.host}:${cfg.port}`;
      if (!state.relayUrls.includes(relayUrl)) {
        state.relayUrls.push(relayUrl);
        persistRelayUrls();
        renderRelayUrls();
        renderRelayUrlSuggestions();
      }
    }
    toast(`Relay started: ${cfg.proto}://${cfg.host}:${cfg.port}`, "success");
  } catch (e) { toast("Relay error: " + e, "error"); }
}

async function handleRelayStop(configId) {
  const info = getRunningInfo(configId);
  if (!info) return;
  try {
    await invoke("relay_stop", { runtimeId: info.runtime_id });
    state.runningRelays = state.runningRelays.filter(r => r.config_id !== configId);
    renderRelayList();
    renderNetFooter();
    if (!state.runningRelays.length) stopRelayPolling();
    toast("Relay stopped.", "info");
  } catch (e) { toast(String(e), "error"); }
}

async function handleRelayDelete(configId) {
  try {
    // relay_delete_config stops the relay server-side if running.
    await invoke("relay_delete_config", { id: configId });
    state.savedRelays    = state.savedRelays.filter(r => r.id !== configId);
    state.runningRelays  = state.runningRelays.filter(r => r.config_id !== configId);
    renderRelayList();
    renderNetFooter();
    if (!state.runningRelays.length) stopRelayPolling();
  } catch (e) { toast("Delete failed: " + e, "error"); }
}

async function copyRelayInvite(info) {
  try {
    await navigator.clipboard.writeText(info.invite_uri);
    toast("Invite link copied.", "success");
  } catch {
    toast("Copy manually: " + info.invite_uri.slice(0, 40) + "…", "info", 5000);
  }
}

async function loadRelayConfigs() {
  if (!IS_TAURI) return;
  try {
    state.savedRelays = await invoke("relay_list_configs");
    renderRelayList();
    renderNetFooter();
    // Auto-start relays that were active when the app was last closed.
    const toStart = state.savedRelays.filter(r => r.active);
    for (const cfg of toStart) {
      try {
        const info = await invoke("relay_start", { configId: cfg.id });
        state.runningRelays.push(info);
      } catch (e) {
        console.warn(`[toloo] auto-start relay ${cfg.id} failed:`, e);
      }
    }
    if (state.runningRelays.length) {
      renderRelayList();
      renderNetFooter();
      startRelayPolling();
    }
  } catch { /* DB not yet initialised or Tauri unavailable */ }
}

async function refreshRelays() {
  if (!IS_TAURI) return;
  try {
    state.runningRelays = await invoke("relay_list");
    renderRelayList();
    renderNetFooter();
  } catch { /* ignore */ }
}

function startRelayPolling() {
  if (state.relayPollTimer) return;
  state.relayPollTimer = setInterval(refreshRelays, 2000);
}

function stopRelayPolling() {
  if (!state.relayPollTimer) return;
  clearInterval(state.relayPollTimer);
  state.relayPollTimer = null;
}


// ══════════════════════════════════════════════════════════════════════
// Mobile back button
// ══════════════════════════════════════════════════════════════════════

function handleBack() {
  document.getElementById("app").classList.remove("chat-open");
  state.activeRoom = null;
  renderRoomsList();
  renderChatView();
}


// ══════════════════════════════════════════════════════════════════════
// Context menu
// ══════════════════════════════════════════════════════════════════════

let _ctxMenu = null;
let _longPressTimer = null;
const LONG_PRESS_MS = 500;

function closeCtxMenu() {
  if (_ctxMenu) { _ctxMenu.remove(); _ctxMenu = null; }
}

/**
 * Show a context menu at (x, y) with given items.
 * items: [{ label, icon, danger?, action }] | "sep"
 */
function showCtxMenu(x, y, items) {
  closeCtxMenu();

  const menu = document.createElement("div");
  menu.className = "ctx-menu";

  items.forEach(item => {
    if (item === "sep") {
      menu.appendChild(document.createElement("div")).className = "ctx-menu-sep";
      return;
    }
    const el = document.createElement("div");
    el.className = "ctx-menu-item" + (item.danger ? " danger" : "");
    el.innerHTML = `<span class="ctx-icon">${item.icon}</span>${escapeHtml(item.label)}`;
    el.addEventListener("click", () => { closeCtxMenu(); item.action(); });
    menu.appendChild(el);
  });

  // Position: keep inside viewport
  document.body.appendChild(menu);
  _ctxMenu = menu;

  const mw = menu.offsetWidth, mh = menu.offsetHeight;
  const vw = window.innerWidth,  vh = window.innerHeight;
  menu.style.left = Math.min(x, vw - mw - 8) + "px";
  menu.style.top  = Math.min(y, vh - mh - 8) + "px";
}

/** Attach right-click + long-press context menu to an element. */
function attachCtxTrigger(el, getItems) {
  // Right-click (desktop)
  el.addEventListener("contextmenu", e => {
    e.preventDefault();
    showCtxMenu(e.clientX, e.clientY, getItems());
  });

  // Long press (touch)
  el.addEventListener("touchstart", e => {
    const touch = e.touches[0];
    const startX = touch.clientX, startY = touch.clientY;
    el.classList.add("ctx-pressing");
    _longPressTimer = setTimeout(() => {
      el.classList.remove("ctx-pressing");
      showCtxMenu(startX, startY, getItems());
    }, LONG_PRESS_MS);
  }, { passive: true });

  el.addEventListener("touchend",   () => { clearTimeout(_longPressTimer); el.classList.remove("ctx-pressing"); }, { passive: true });
  el.addEventListener("touchmove",  () => { clearTimeout(_longPressTimer); el.classList.remove("ctx-pressing"); }, { passive: true });
  el.addEventListener("touchcancel",() => { clearTimeout(_longPressTimer); el.classList.remove("ctx-pressing"); }, { passive: true });
}

// Dismiss on click/scroll outside
document.addEventListener("pointerdown", e => {
  if (_ctxMenu && !_ctxMenu.contains(e.target)) closeCtxMenu();
}, true);
document.addEventListener("scroll", closeCtxMenu, true);
document.addEventListener("keydown", e => { if (e.key === "Escape") closeCtxMenu(); });

// ── Context menu actions ──────────────────────────────────────────────

function msgCtxItems(msg, room) {
  const isOwn = state.node && msg.author === state.node.sig_pub;
  const items = [
    {
      label: "Details", icon: "ℹ",
      action() {
        const lines = [
          `Author: ${msg.author}`,
          `Time:   ${new Date(msg.ts).toLocaleString()}`,
          `Status: ${msgStatusLabel(msg)}`,
          `Depth:  ${msg.depth ?? 1}`,
          `EID:    ${msg.eid ?? "—"}`,
        ];
        alert(lines.join("\n"));
      }
    },
    {
      label: "Copy text", icon: "⎘",
      action() { navigator.clipboard.writeText(msg.body).catch(() => {}); }
    },
  ];
  if (!isOwn) {
    items.push("sep");
    items.push({
      label: "Flag message", icon: "⚑",
      action() { handleFlagMessage(msg, room); }
    });
    items.push({
      label: "Attest (positive)", icon: "👍",
      action() { handleAttest(msg.author, "positive"); }
    });
    items.push({
      label: "Attest (negative)", icon: "👎",
      action() { handleAttest(msg.author, "negative"); }
    });
    if (!isBlocked(msg.author)) {
      items.push({
        label: "Block user", icon: "🚫", danger: true,
        action() { handleBlockNode(msg.author); }
      });
    }
  }
  if (isOwn) {
    items.push("sep");
    items.push({
      label: "Delete locally", icon: "🗑", danger: true,
      action() {
        room.messages = room.messages.filter(m => m !== msg);
        saveState();
        renderMessages();
      }
    });
  }
  return items;
}

function roomCtxItems(room) {
  return [
    {
      label: "Details", icon: "ℹ",
      action() {
        const lines = [
          `Name:     ${roomLabel(room)}`,
          `Key:      ${room.pub}`,
          `Messages: ${room.messages.length}`,
        ];
        if (room.inviteUri) lines.push(`Invite:   ${room.inviteUri}`);
        alert(lines.join("\n"));
      }
    },
    "sep",
    {
      label: "Leave / remove room", icon: "🚪", danger: true,
      action() {
        if (!confirm(`Remove "${roomLabel(room)}" from your room list?`)) return;
        state.rooms.delete(room.pub);
        if (state.activeRoom === room.pub) {
          state.activeRoom = null;
          renderChatView();
        }
        saveState();
        renderRoomsList();
      }
    },
  ];
}

// ══════════════════════════════════════════════════════════════════════
// Event bindings
// ══════════════════════════════════════════════════════════════════════

function bindEvents() {
  // Sidebar
  $("btn-identity").addEventListener("click", () => {
    renderRelayUrls();
    renderRelayUrlSuggestions();
    renderBlocklist();
    openModal("identity-modal");
  });
  $("btn-new-chat").addEventListener("click", () => {
    if (!IS_TAURI) { toast("Native backend required.", "error"); return; }
    openModal("add-room-modal");
  });
  $("search-input").addEventListener("input", renderRoomsList);

  // Chat header
  $("btn-back").addEventListener("click", handleBack);
  $("btn-sync").addEventListener("click", handleSync);
  $("btn-share").addEventListener("click", handleShareRoom);
  $("btn-export").addEventListener("click", handleExportMessages);

  // Compose
  $("compose-form").addEventListener("submit", handleSend);

  // Identity sheet
  $("btn-keygen").addEventListener("click", handleKeygen);
  $("btn-load-identity").addEventListener("click", handleLoadIdentity);
  $("btn-save-identity").addEventListener("click", handleSaveIdentity);
  // Encrypted identity
  $("btn-encrypt-save").addEventListener("click", handleEncryptSave);
  $("btn-load-encrypted").addEventListener("click", handleLoadEncrypted);
  $("encrypted-file-input").addEventListener("change", async () => {
    const file = $("encrypted-file-input").files[0];
    if (!file) return;
    const blob = await file.text();
    LS.set("toloo_encrypted_node", blob.trim());
    toast("Encrypted identity imported. Enter passphrase to unlock.", "info");
    $("encrypted-file-input").value = "";
  });
  $("btn-clear-identity").addEventListener("click", () => {
    clearNode();
    toast("Identity removed.");
  });
  // Relay URL list in identity sheet
  $("btn-relay-url-add").addEventListener("click", () => {
    addRelayUrl($("relay-url-input").value);
    $("relay-url-input").value = "";
  });
  $("relay-url-input").addEventListener("keydown", e => {
    if (e.key !== "Enter") return;
    e.preventDefault();
    addRelayUrl($("relay-url-input").value);
    $("relay-url-input").value = "";
  });

  // Direction toggle
  document.querySelectorAll("[data-dir]").forEach(btn =>
    btn.addEventListener("click", () => applyDir(btn.dataset.dir))
  );

  // Tab bars
  document.querySelectorAll(".tab-bar").forEach(bindTabs);

  // Import sheet (global)
  $("btn-import-global").addEventListener("click", () => {
    clearImportModal();
    openModal("import-modal");
  });
  $("btn-import-text").addEventListener("click", () =>
    importAll($("import-text-input").value)
  );
  $("import-text-input").addEventListener("keydown", e => {
    // Ctrl/Cmd+Enter triggers decode.
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      importAll($("import-text-input").value);
    }
  });
  $("btn-import-file-open").addEventListener("click", () => $("toloo-file-input").click());
  $("btn-import-apply").addEventListener("click", applyImport);
  $("btn-import-clear").addEventListener("click", clearImportModal);

  // .toloo file picker (used by import modal)
  $("toloo-file-input").addEventListener("change", async () => {
    const file = $("toloo-file-input").files[0];
    if (!file) return;
    clearImportModal();
    openModal("import-modal");
    const text = await file.text();
    // Show filename in the textarea as a hint; decode uses the file text.
    $("import-text-input").placeholder = file.name;
    await importAll(text);
  });

  // Create / join buttons
  $("btn-create-room").addEventListener("click", handleCreateRoom);
  $("btn-join-room").addEventListener("click", handleJoinRoom);

  // Share sheet
  $("btn-copy-uri").addEventListener("click", handleCopyUri);
  $("btn-save-toloo").addEventListener("click", handleSaveToloo);

  // Relay manager
  $("btn-manage-relays").addEventListener("click", () => {
    refreshRelays();
    renderRelayList();
    openModal("relay-modal");
  });
  $("btn-relay-add").addEventListener("click",         showRelayForm);
  $("btn-relay-form-cancel").addEventListener("click", hideRelayForm);
  $("btn-relay-save").addEventListener("click",        handleRelaySave);
  $("btn-detect-ip").addEventListener("click", () => {
    if (IS_TAURI) {
      invoke("detect_lan_ip_cmd").then(ip => { $("relay-host").value = ip; }).catch(() => {});
    }
  });
  $("relay-proto").addEventListener("change", updateRelayForm);
  $("relay-skin").addEventListener("change",  updateRelayForm);

  // Close buttons
  document.querySelectorAll(".btn-close").forEach(btn =>
    btn.addEventListener("click", () => closeModal(btn.dataset.close))
  );

  // Dismiss overlay by clicking backdrop
  $("overlay").addEventListener("click", e => {
    if (e.target === $("overlay")) {
      $("overlay").querySelectorAll(".sheet:not(.hidden)").forEach(s => closeModal(s.id));
    }
  });

  // Esc closes open modal
  document.addEventListener("keydown", e => {
    if (e.key !== "Escape") return;
    const open = $("overlay").querySelector(".sheet:not(.hidden)");
    if (open) closeModal(open.id);
  });
}


// ══════════════════════════════════════════════════════════════════════
// Init
// ══════════════════════════════════════════════════════════════════════

async function init() {
  initDir();
  loadPersistedState();
  bindEvents();
  renderRoomsList();
  renderChatView();

  if (!IS_TAURI) {
    toast("Running in browser mode — native features unavailable.", "error", 6000);
    return;
  }

  const savedNode = LS.get("toloo_node");
  if (savedNode) {
    try {
      const info = await invoke("load_node", { nodeJson: savedNode });
      applyNode(info);
    } catch {
      LS.rm("toloo_node");
    }
  }

  // If no plaintext node, check for encrypted one.
  if (!state.node && LS.get("toloo_encrypted_node")) {
    // User will need to enter passphrase — show a hint.
    toast("Encrypted identity found. Open Identity & Settings to unlock.", "info", 5000);
  }

  await loadRelayConfigs();
  await loadBlocklist();
}

init();
