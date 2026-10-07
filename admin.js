/* Script2Video — admin panel (static, runs entirely in the browser).
 *
 * Storage = this GitHub repo:
 *   vault.json       admin-password–encrypted {gh_token, sign_jwk, data_key}
 *   admin_data.json  full user records, AES-GCM with data_key (admin only)
 *   licenses.json    {payload, sig}: payload is signed (ECDSA P-256/SHA-256);
 *                    each user's entry is AES-GCM encrypted with a key derived
 *                    from THAT user's password, keyed by sha256("s2v:"+username).
 * The desktop app embeds the public key and verifies the signature, so the
 * file cannot be forged or edited by anyone without the admin password.
 */
"use strict";

const CFG = { owner: "alaamohamed12-code", repo: "script2video-admin", branch: "main" };
const VAULT_ITER = 600000;   // admin password → vault key
const USER_ITER = 150000;    // user password → entry key (the desktop app derives the same)
const DAY = 86400000;

// Section ids are shared with the desktop app (modules/licensing/sections.py).
const SECTIONS = [
    { id: "broll", label: "📢 محتوى وثائقي B-Roll", content: true },
    { id: "montage", label: "🎞️ مونتاج وثائقي" },
    { id: "kids_songs", label: "🎵 محتوى أغاني أطفال", content: true },
    { id: "anime2d", label: "🎬 2D Anime Style", content: true },
    { id: "doc3d", label: "🧊 3D Doc", content: true },
    { id: "vox", label: "📰 فوكس ستايل", content: true },
    { id: "vox2", label: "📰 فوكس ستايل 2", content: true },
    { id: "dark_vox", label: "🎧 Dark Vox Style", content: true },
    { id: "studio", label: "🎞️ Parallax Studio", content: true },
    { id: "motion", label: "☁️ Motion Story" },
    { id: "production", label: "🎬 الإنتاج" },
    { id: "social", label: "📱 السوشيال ميديا" },
    { id: "shorts", label: "🗓️ جدولة شورتس" },
    { id: "remix", label: "🎵 ريمكس تيك توك" },
];
const SECTION_IDS = SECTIONS.map(s => s.id);
const CONTENT_IDS = SECTIONS.filter(s => s.content).map(s => s.id);

const S = {
    pass: null,          // admin password (kept in memory only while logged in)
    vault: null,         // decrypted vault
    dataKey: null,       // CryptoKey (AES-GCM) for admin_data.json
    signKey: null,       // CryptoKey (ECDSA private)
    users: [],           // admin_data.users
    lic: null,           // parsed current licenses payload
    editing: null,       // username being edited (null = new)
    saving: Promise.resolve(),
};

// ── encoding helpers ────────────────────────────────────────────────────────
const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = buf => { const b = new Uint8Array(buf); let s = ""; for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000)); return btoa(s); };
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const utf8b64 = str => b64(enc.encode(str));
const b64utf8 = s => dec.decode(unb64(s));
const rand = n => crypto.getRandomValues(new Uint8Array(n));
async function sha256hex(str) {
    const h = await crypto.subtle.digest("SHA-256", enc.encode(str));
    return [...new Uint8Array(h)].map(x => x.toString(16).padStart(2, "0")).join("");
}
const lookupId = username => sha256hex("s2v:" + username.trim().toLowerCase());

// ── crypto helpers ──────────────────────────────────────────────────────────
async function pbkdf2Key(password, salt, iter) {
    const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations: iter },
        base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function aesEncrypt(key, obj) {
    const iv = rand(12);
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(obj)));
    return { iv: b64(iv), ct: b64(ct) };
}
async function aesDecrypt(key, box) {
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(box.iv) }, key, unb64(box.ct));
    return JSON.parse(dec.decode(pt));
}
async function openVault(vaultFile, password) {
    const key = await pbkdf2Key(password, unb64(vaultFile.salt), vaultFile.iter);
    return aesDecrypt(key, vaultFile);   // throws on wrong password
}
async function sealVault(vault, password) {
    const salt = rand(16);
    const key = await pbkdf2Key(password, salt, VAULT_ITER);
    return { kdf: "PBKDF2-SHA256", iter: VAULT_ITER, salt: b64(salt), ...(await aesEncrypt(key, vault)) };
}

// ── Cairo time helpers (inputs/outputs are Africa/Cairo wall-clock) ──────────
const CAIRO = "Africa/Cairo";
function tzOffsetMs(epoch) {
    const p = Object.fromEntries(new Intl.DateTimeFormat("en-US", {
        timeZone: CAIRO, hourCycle: "h23", year: "numeric", month: "2-digit", day: "2-digit",
        hour: "2-digit", minute: "2-digit", second: "2-digit",
    }).formatToParts(new Date(epoch)).map(x => [x.type, x.value]));
    const asUtc = Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour, +p.minute, +p.second);
    return asUtc - Math.floor(epoch / 1000) * 1000;
}
function cairoInputToEpoch(v) {               // "2026-10-10T20:00" → epoch ms
    const [d, t] = v.split("T"); const [y, m, dd] = d.split("-").map(Number); const [hh, mi] = t.split(":").map(Number);
    const wall = Date.UTC(y, m - 1, dd, hh, mi);
    let e = wall - tzOffsetMs(wall);
    e = wall - tzOffsetMs(e);
    return e;
}
function epochToCairoInput(e) {
    const w = new Date(e + tzOffsetMs(e));
    const pad = n => String(n).padStart(2, "0");
    return `${w.getUTCFullYear()}-${pad(w.getUTCMonth() + 1)}-${pad(w.getUTCDate())}T${pad(w.getUTCHours())}:${pad(w.getUTCMinutes())}`;
}
const fmtCairo = e => new Intl.DateTimeFormat("ar-EG", { timeZone: CAIRO, dateStyle: "medium", timeStyle: "short" }).format(new Date(e));

// ── GitHub API ──────────────────────────────────────────────────────────────
const API = `https://api.github.com/repos/${CFG.owner}/${CFG.repo}`;
async function gh(path, opts = {}, token = S.vault?.gh_token) {
    const headers = { "Accept": "application/vnd.github+json", ...(opts.headers || {}) };
    if (token) headers["Authorization"] = `Bearer ${token}`;
    const r = await fetch(API + path, { ...opts, headers, cache: "no-store" });
    if (!r.ok) {
        const t = await r.text().catch(() => "");
        throw new Error(`GitHub ${r.status}: ${t.slice(0, 200)}`);
    }
    return r.status === 204 ? null : r.json();
}
async function ghReadJson(file, token) {
    const j = await gh(`/contents/${file}?ref=${CFG.branch}&t=${Date.now()}`, {}, token);
    return JSON.parse(b64utf8(j.content.replace(/\n/g, "")));
}
async function ghCommit(files, message) {
    // One atomic commit for all files (Git Data API).
    const ref = await gh(`/git/ref/heads/${CFG.branch}`);
    const head = await gh(`/git/commits/${ref.object.sha}`);
    const tree = await gh(`/git/trees`, { method: "POST", body: JSON.stringify({
        base_tree: head.tree.sha,
        tree: Object.entries(files).map(([path, content]) => ({ path, mode: "100644", type: "blob", content })),
    }) });
    const commit = await gh(`/git/commits`, { method: "POST", body: JSON.stringify({
        message, tree: tree.sha, parents: [ref.object.sha],
    }) });
    await gh(`/git/refs/heads/${CFG.branch}`, { method: "PATCH", body: JSON.stringify({ sha: commit.sha }) });
    return commit.sha;
}

// ── license building ────────────────────────────────────────────────────────
function normalizeSections(list) {
    const set = new Set(list.filter(s => SECTION_IDS.includes(s)));
    if (CONTENT_IDS.some(s => set.has(s))) set.add("production");
    return SECTION_IDS.filter(s => set.has(s));
}
async function fingerprint(u) {
    return sha256hex(JSON.stringify([u.username.toLowerCase(), u.password, u.sections, u.start, u.end, !!u.suspended]));
}
async function buildLicenses() {
    const prevEntries = (S.lic && S.lic.users) || {};
    const users = {};
    for (const u of S.users) {
        const lid = await lookupId(u.username);
        const fp = await fingerprint(u);
        if (u._fp === fp && prevEntries[lid]) { users[lid] = prevEntries[lid]; continue; }
        const salt = rand(16);
        const key = await pbkdf2Key(u.password, salt, USER_ITER);
        const box = await aesEncrypt(key, {
            l: lid, u: u.username, sections: u.sections, start: u.start, end: u.end, suspended: !!u.suspended,
        });
        users[lid] = { s: b64(salt), ...box };
        u._fp = fp;
    }
    const prevIssued = (S.lic && S.lic.issued_at) || 0;
    const payload = { v: 1, issued_at: Math.max(Date.now(), prevIssued + 1), iter: USER_ITER, users };
    const payloadStr = JSON.stringify(payload);
    const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, S.signKey, enc.encode(payloadStr));
    S.lic = payload;
    return JSON.stringify({ payload: payloadStr, sig: b64(sig) });
}
async function persist(message) {
    // Serialize saves so quick consecutive actions never race on the branch ref.
    const run = async () => {
        showBusy(true, "جاري الحفظ والتوقيع والرفع إلى GitHub...");
        try {
            const licensesJson = await buildLicenses();
            const adminData = await aesEncrypt(S.dataKey, { users: S.users, updated_at: Date.now() });
            const sha = await ghCommit({
                "licenses.json": licensesJson,
                "admin_data.json": JSON.stringify(adminData),
            }, message);
            setStatus(`✅ تم الحفظ (${sha.slice(0, 7)}) — يصل التغيير للبرامج خلال دقائق (فحص كل 10 دقائق).`, "ok");
        } catch (e) {
            setStatus("❌ فشل الحفظ: " + e.message + " — أعد تحميل الصفحة وحاول مرة أخرى.", "err");
            throw e;
        } finally {
            showBusy(false);
        }
    };
    S.saving = S.saving.then(run, run);
    return S.saving;
}

// ── UI helpers ──────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const esc = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
function showBusy(on, text) { $("busy").classList.toggle("hidden", !on); if (text) $("busyText").textContent = text; }
function setStatus(text, kind) { const el = $("statusLine"); el.textContent = text; el.style.color = kind === "err" ? "var(--bad)" : kind === "ok" ? "var(--ok)" : ""; }
function setMsg(id, text, kind) { const el = $(id); el.textContent = text; el.className = "msg " + (kind || ""); }
function statusOf(u, now = Date.now()) {
    if (u.suspended) return { key: "suspended", label: "موقوف", cls: "b-suspended" };
    if (now < u.start) return { key: "pending", label: "لم يبدأ", cls: "b-pending" };
    if (now >= u.end) return { key: "expired", label: "منتهٍ", cls: "b-expired" };
    return { key: "active", label: "نشط", cls: "b-active" };
}
function remainingText(u, now = Date.now()) {
    if (now >= u.end) return "—";
    const ms = u.end - Math.max(now, u.start);
    const d = Math.floor(ms / DAY), h = Math.floor((ms % DAY) / 3600000);
    return d > 0 ? `${d} يوم ${h ? "و" + h + " ساعة" : ""}` : `${h} ساعة`;
}

function render() {
    const q = $("searchBox").value.trim().toLowerCase();
    const now = Date.now();
    const list = S.users.filter(u => !q || u.username.toLowerCase().includes(q))
        .sort((a, b) => a.username.localeCompare(b.username));
    const counts = { active: 0, expired: 0, pending: 0, suspended: 0 };
    S.users.forEach(u => counts[statusOf(u, now).key]++);
    $("stats").innerHTML = `
        <span class="stat">الإجمالي: ${S.users.length}</span>
        <span class="stat">نشط: ${counts.active}</span>
        <span class="stat">منتهٍ: ${counts.expired}</span>
        <span class="stat">لم يبدأ: ${counts.pending}</span>
        <span class="stat">موقوف: ${counts.suspended}</span>`;
    $("emptyState").classList.toggle("hidden", S.users.length > 0);
    $("usersBody").innerHTML = list.map(u => {
        const st = statusOf(u, now);
        const name = esc(u.username);
        return `<tr data-user="${name}">
            <td class="uname">${name}</td>
            <td><span class="badge ${st.cls}">${st.label}</span></td>
            <td>${fmtCairo(u.start)}</td>
            <td>${fmtCairo(u.end)}</td>
            <td>${remainingText(u, now)}</td>
            <td title="${esc(u.sections.map(id => (SECTIONS.find(s => s.id === id) || {}).label || id).join("\n"))}">${u.sections.length} / ${SECTIONS.length}</td>
            <td><div class="actions">
                <button class="btn btn-ghost btn-sm" data-act="edit">✏️ تعديل</button>
                <button class="btn btn-ghost btn-sm" data-act="ext" data-days="7">+7</button>
                <button class="btn btn-ghost btn-sm" data-act="ext" data-days="30">+30</button>
                <button class="btn btn-ghost btn-sm" data-act="ext" data-days="90">+90</button>
                <button class="btn btn-ghost btn-sm" data-act="suspend">${u.suspended ? "▶️ استئناف" : "⏸️ إيقاف"}</button>
                <button class="btn btn-ghost btn-sm" data-act="delete">🗑️ حذف</button>
            </div></td>
        </tr>`;
    }).join("");
}

// ── login ───────────────────────────────────────────────────────────────────
async function login(password) {
    let vaultFile;
    try { vaultFile = await ghReadJson("vault.json", null); }
    catch (e) { vaultFile = await (await fetch("vault.json?t=" + Date.now(), { cache: "no-store" })).json(); }
    let vault;
    try { vault = await openVault(vaultFile, password); }
    catch (e) { throw new Error("كلمة المرور غير صحيحة"); }
    S.vault = vault;
    S.pass = password;
    S.dataKey = await crypto.subtle.importKey("raw", unb64(vault.data_key), "AES-GCM", false, ["encrypt", "decrypt"]);
    S.signKey = await crypto.subtle.importKey("jwk", vault.sign_jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
    const adminData = await ghReadJson("admin_data.json");
    S.users = (await aesDecrypt(S.dataKey, adminData)).users || [];
    const lic = await ghReadJson("licenses.json");
    S.lic = JSON.parse(lic.payload);
}

$("loginForm").addEventListener("submit", async ev => {
    ev.preventDefault();
    setMsg("loginMsg", "جاري فتح الخزنة...", "");
    $("btnLogin").disabled = true;
    try {
        await login($("adminPass").value);
        $("adminPass").value = "";
        $("loginView").classList.add("hidden");
        $("dashView").classList.remove("hidden");
        $("topActions").classList.remove("hidden");
        render();
    } catch (e) {
        setMsg("loginMsg", e.message, "err");
    } finally {
        $("btnLogin").disabled = false;
    }
});
$("btnLogout").addEventListener("click", () => location.reload());

// ── user editor ─────────────────────────────────────────────────────────────
$("sectionsGrid").innerHTML = SECTIONS.map(s =>
    `<label><input type="checkbox" value="${s.id}"> ${s.label}</label>`).join("");
const sectionBoxes = () => [...$("sectionsGrid").querySelectorAll("input")];
$("sectionsGrid").addEventListener("change", ev => {
    if (CONTENT_IDS.includes(ev.target.value) && ev.target.checked) {
        sectionBoxes().find(b => b.value === "production").checked = true;
    }
});
$("btnAllSections").onclick = () => sectionBoxes().forEach(b => b.checked = true);
$("btnNoSections").onclick = () => sectionBoxes().forEach(b => b.checked = false);
$("btnCopyPass").onclick = () => navigator.clipboard.writeText($("fPassword").value);
document.querySelectorAll(".quick-dur .chip").forEach(c => c.onclick = () => {
    const start = $("fStart").value ? cairoInputToEpoch($("fStart").value) : Date.now();
    $("fEnd").value = epochToCairoInput(start + Number(c.dataset.dur) * DAY);
});
document.querySelectorAll("[data-close]").forEach(b => b.onclick = () => b.closest(".modal").classList.add("hidden"));

function openEditor(u) {
    S.editing = u ? u.username : null;
    $("userModalTitle").textContent = u ? `تعديل: ${u.username}` : "مستخدم جديد";
    $("fUsername").value = u ? u.username : "";
    $("fUsername").disabled = !!u;
    $("fPassword").value = u ? u.password : "";
    const now = Date.now();
    $("fStart").value = epochToCairoInput(u ? u.start : now);
    $("fEnd").value = epochToCairoInput(u ? u.end : now + 30 * DAY);
    const set = new Set(u ? u.sections : []);
    sectionBoxes().forEach(b => b.checked = set.has(b.value));
    $("fSuspended").checked = !!(u && u.suspended);
    setMsg("userFormMsg", "");
    $("userModal").classList.remove("hidden");
    (u ? $("fPassword") : $("fUsername")).focus();
}
$("btnAddUser").onclick = () => openEditor(null);

$("userForm").addEventListener("submit", async ev => {
    ev.preventDefault();
    const username = $("fUsername").value.trim();
    const password = $("fPassword").value;
    const start = cairoInputToEpoch($("fStart").value);
    const end = cairoInputToEpoch($("fEnd").value);
    const sections = normalizeSections(sectionBoxes().filter(b => b.checked).map(b => b.value));
    if (!/^[^\s]{3,64}$/.test(username)) return setMsg("userFormMsg", "اسم المستخدم 3 أحرف على الأقل وبدون مسافات", "err");
    if (password.length < 4) return setMsg("userFormMsg", "كلمة المرور 4 أحرف على الأقل", "err");
    if (end <= start) return setMsg("userFormMsg", "موعد الانتهاء يجب أن يكون بعد موعد البدء", "err");
    if (!sections.length) return setMsg("userFormMsg", "اختر قسماً واحداً على الأقل", "err");
    const exists = S.users.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (!S.editing && exists) return setMsg("userFormMsg", "اسم المستخدم موجود بالفعل", "err");
    const backup = JSON.stringify(S.users);
    if (S.editing) {
        Object.assign(exists, { password, start, end, sections, suspended: $("fSuspended").checked, updated_at: Date.now() });
    } else {
        S.users.push({ username, password, start, end, sections, suspended: $("fSuspended").checked, created_at: Date.now() });
    }
    try {
        await persist(`${S.editing ? "update" : "create"} user`);
        $("userModal").classList.add("hidden");
    } catch (e) {
        S.users = JSON.parse(backup);
        setMsg("userFormMsg", "فشل الحفظ: " + e.message, "err");
    }
    render();
});

// ── row actions ─────────────────────────────────────────────────────────────
$("usersBody").addEventListener("click", async ev => {
    const btn = ev.target.closest("button[data-act]");
    if (!btn) return;
    const name = btn.closest("tr").dataset.user;
    const u = S.users.find(x => x.username === name);
    if (!u) return;
    const act = btn.dataset.act;
    if (act === "edit") return openEditor(u);
    const backup = JSON.stringify(S.users);
    let msg;
    if (act === "ext") {
        const days = Number(btn.dataset.days);
        u.end = Math.max(u.end, Date.now()) + days * DAY;
        msg = `extend user +${days}d`;
    } else if (act === "suspend") {
        u.suspended = !u.suspended;
        msg = u.suspended ? "suspend user" : "resume user";
    } else if (act === "delete") {
        if (!confirm(`حذف المستخدم «${u.username}» نهائياً؟`)) return;
        S.users = S.users.filter(x => x !== u);
        msg = "delete user";
    }
    try { await persist(msg); } catch (e) { S.users = JSON.parse(backup); }
    render();
});
$("searchBox").addEventListener("input", render);

// ── change admin password ───────────────────────────────────────────────────
$("btnChangePass").onclick = () => { $("passForm").reset(); setMsg("passMsg", ""); $("passModal").classList.remove("hidden"); };
$("passForm").addEventListener("submit", async ev => {
    ev.preventDefault();
    if ($("pOld").value !== S.pass) return setMsg("passMsg", "كلمة المرور الحالية غير صحيحة", "err");
    if ($("pNew").value !== $("pNew2").value) return setMsg("passMsg", "التأكيد غير مطابق", "err");
    if ($("pNew").value.length < 10) return setMsg("passMsg", "10 أحرف على الأقل", "err");
    showBusy(true, "جاري إعادة تشفير الخزنة...");
    try {
        const sealed = await sealVault(S.vault, $("pNew").value);
        await ghCommit({ "vault.json": JSON.stringify(sealed) }, "rotate admin password");
        S.pass = $("pNew").value;
        $("passModal").classList.add("hidden");
        setStatus("✅ تم تغيير كلمة مرور الأدمن. احفظها في مكان آمن — لا يمكن استرجاعها.", "ok");
    } catch (e) {
        setMsg("passMsg", "فشل: " + e.message, "err");
    } finally {
        showBusy(false);
    }
});

// refresh "remaining"/status columns every minute
setInterval(() => { if (!$("dashView").classList.contains("hidden")) render(); }, 60000);
