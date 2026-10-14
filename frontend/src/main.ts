import "./style.css";
import {
  escapeHTML as esc,
  severityLabels,
  validityLabel,
  validityTone,
  formatDate,
  plural,
  availableConversions,
  pfxPasswordProblem,
  sortFiles,
} from "./presentation.mjs";
import type { Certificate, Chain, View } from "./types";

const icon = `<svg viewBox="0 0 48 48" aria-hidden="true"><rect x="4" y="4" width="40" height="40" rx="10" fill="#17263a"/><rect x="11" y="11" width="22" height="27" rx="3" fill="#e7edf6"/><path d="M15 18h14M15 23h14M15 28h8" stroke="#6d84a3" stroke-width="2.2" stroke-linecap="round"/><circle cx="33" cy="32" r="10" fill="#17263a"/><circle cx="33" cy="32" r="8.5" fill="#dfad68"/><path d="m29.2 32 2.6 2.6 4.6-5" fill="none" stroke="#17263a" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
const notInV1 =
  "Not in v1.0: revocation checks (OCSP/CRL), downloading missing certificates (AIA), trust-store validation, CSR generation, signing and editing.";

const root = document.querySelector<HTMLDivElement>("#app")!;
root.innerHTML = `<header class="topbar"><div class="brand">${icon}<div><strong>Certificate Doctor</strong><span>ALMARFELD <i>·</i> v1.0.0</span></div></div><span class="offline"><b></b> Offline · nothing leaves this PC</span><div class="top-actions"><button id="clear" class="ghost" hidden>Close all</button><button id="open" class="primary">Open files…</button></div></header>
<div id="notice" class="notice" role="status" aria-live="polite" hidden></div>
<main>
<section id="empty" class="empty"><div class="large-icon">${icon}</div><p class="eyebrow">CERTIFICATES, WITHOUT THE GUESSWORK</p><h1>Inspect, check and convert certificates offline.</h1><p class="lead">See subject, issuer, validity, SAN and fingerprints. Check the chain and whether the private key matches.<br>Convert a copy between PEM, DER, P7B and PFX.</p><button id="open-empty" class="primary">Open certificate files…</button><p class="drop-hint">Or drop one or more files anywhere in this window</p><div class="formats"><span>.cer</span><span>.crt</span><span>.pem</span><span>.der</span><span>.pfx</span><span>.p12</span><span>.p7b</span><span>.key</span></div><div class="empty-features"><span>No network or accounts</span><span>Passwords stay in memory</span><span>Originals never modified</span></div><p class="limits">${esc(notInV1)}</p></section>
<div id="loaded" class="workspace" hidden>
<aside>
<section class="panel"><div class="panel-heading"><h2>Files</h2><span class="tiny" id="file-count"></span></div><ul id="files" class="files"></ul><button id="add" class="secondary full">Add files…</button><p class="help">Add the certificate, its intermediates and the private key together to check the chain and the key match.</p></section>
<section class="panel"><div class="panel-heading"><h2>Settings</h2></div><label for="soon">Warn when a certificate expires within</label><select id="soon"><option value="7">7 days</option><option value="14">14 days</option><option value="30">30 days</option><option value="60">60 days</option><option value="90">90 days</option></select></section>
<section class="panel"><div class="panel-heading"><h2>Report</h2></div><p class="help">Reports list certificates, fingerprints and findings. Private keys and passwords are never included.</p><div class="row"><button id="report-html" class="secondary">Save HTML…</button><button id="report-json" class="secondary">Save JSON…</button></div></section>
<section class="panel limits-panel"><div class="panel-heading"><h2>Not checked</h2></div><ul id="limitations"></ul></section>
</aside>
<div class="content">
<section id="verdict" class="verdict"></section>
<section class="panel"><div class="panel-heading"><h2>Findings</h2><span class="tiny" id="finding-count"></span></div><div id="findings"></div></section>
<section class="panel"><div class="panel-heading"><h2>Chains</h2><span class="tiny">Built only from the files you opened</span></div><div id="chains"></div></section>
<section class="panel"><div class="panel-heading"><h2>Certificates</h2><span class="tiny" id="cert-count"></span></div><div id="certificates"></div></section>
<section class="panel" id="keys-panel"><div class="panel-heading"><h2>Private keys</h2><span class="tiny">Key material is never displayed</span></div><div id="keys"></div></section>
</div></div></main>
<footer><span>No telemetry · No uploads · No automatic downloads</span><span id="status">Ready</span></footer>
<dialog id="convert-dialog" aria-labelledby="convert-title"><form method="dialog" id="convert-form"><h2 id="convert-title">Convert a copy</h2><p class="help" id="convert-subject"></p><fieldset id="targets"><legend>Output format</legend></fieldset><div id="key-warning" class="caution" hidden>The private key will be written <strong>unencrypted</strong>. Anyone with this file can use the key. Store it securely and delete copies you do not need.</div><div id="pfx-fields" hidden><label for="pfx-password">New PFX password</label><input id="pfx-password" type="password" autocomplete="new-password"><label for="pfx-confirm">Confirm password</label><input id="pfx-confirm" type="password" autocomplete="new-password"><p class="help">Encrypted with AES-256 (compatible with Windows 10 1709+, OpenSSL 1.1.1+ and Java 11+). The password is not stored.</p></div><p id="convert-error" class="field-error" role="alert"></p><div class="dialog-actions"><button value="cancel" class="ghost" id="convert-cancel">Cancel</button><button id="convert-save" class="primary" value="default">Save copy…</button></div><p class="tiny">A new file is always created. Existing files and the original are never overwritten.</p></form></dialog>`;

const $ = <T extends HTMLElement = HTMLElement>(id: string) =>
  document.getElementById(id) as T;
const api = () => {
  const a = window.go?.main.App;
  if (!a) throw new Error("Desktop backend is unavailable. Run CertificateDoctor.exe.");
  return a;
};

let view: View | null = null;
let busy = false;
let convertLeaf = "";

function notice(message: string, tone: "error" | "ok" | "" = "") {
  const n = $("notice");
  n.textContent = message;
  n.hidden = !message;
  n.className = "notice" + (tone ? " " + tone : "");
}
function status(message: string) {
  $("status").textContent = message;
}
function errorText(e: unknown) {
  return e instanceof Error ? e.message : String(e);
}

async function task(label: string, op: () => Promise<void>) {
  if (busy) return;
  busy = true;
  document.body.classList.add("busy");
  status(label);
  try {
    await op();
  } catch (e) {
    notice(errorText(e), "error");
  } finally {
    busy = false;
    document.body.classList.remove("busy");
    status("Ready");
  }
}

function apply(v: View) {
  view = v;
  if (v.rejected.length) notice("Skipped: " + v.rejected.join("; "), "error");
  render();
}

function render() {
  if (!view) return;
  const v = view;
  const a = v.analysis;
  const loaded = v.files.length > 0;
  $("empty").hidden = loaded;
  $("loaded").hidden = !loaded;
  $("clear").hidden = !loaded;
  if (!loaded) return;
  $<HTMLSelectElement>("soon").value = String(v.expiringSoonDays);
  $("file-count").textContent = plural(v.files.length, "file");

  $("files").innerHTML = sortFiles(v.files)
    .map((f) => {
      const meta =
        f.state === "ready"
          ? `${esc(f.format)} · ${plural(f.certificates, "certificate")}${f.keys ? " · " + plural(f.keys, "key") : ""}`
          : f.state === "password"
            ? "Password protected"
            : "Not loaded";
      const body =
        f.state === "password"
          ? `<form class="unlock" data-id="${esc(f.id)}"><label class="sr" for="pw-${esc(f.id)}">Password for ${esc(f.name)}</label><input id="pw-${esc(f.id)}" type="password" placeholder="PFX password" autocomplete="off"><button class="primary small">Open</button></form>${f.error ? `<p class="field-error">${esc(f.error)}</p>` : ""}`
          : f.state === "error"
            ? `<p class="field-error">${esc(f.error)}</p>`
            : "";
      return `<li class="file ${esc(f.state)}"><div class="file-head"><span class="file-dot"></span><div><strong title="${esc(f.name)}">${esc(f.name)}</strong><small>${meta}</small></div><button class="remove" data-id="${esc(f.id)}" aria-label="Close ${esc(f.name)}" title="Close">×</button></div>${body}</li>`;
    })
    .join("");

  if (!document.activeElement || document.activeElement === document.body)
    document.querySelector<HTMLInputElement>("form.unlock input")?.focus();

  $("limitations").innerHTML = a.limitations.map((l) => `<li>${esc(l)}</li>`).join("");

  const c = a.counts;
  $("verdict").className = "verdict " + a.verdict;
  $("verdict").innerHTML = `<div><span class="eyebrow">RESULT</span><h1>${esc(a.verdictText)}</h1><p>${plural(a.certificates.length, "certificate")} · ${plural(a.keys.length, "private key")} · checked ${esc(formatDate(a.generatedAt))}</p></div><div class="counts"><span class="error"><b>${c.error ?? 0}</b> errors</span><span class="warning"><b>${c.warning ?? 0}</b> warnings</span><span class="info"><b>${c.info ?? 0}</b> notes</span><span class="ok"><b>${c.ok ?? 0}</b> passed</span></div>`;

  $("finding-count").textContent = plural(a.findings.length, "finding");
  $("findings").innerHTML = a.findings.length
    ? a.findings
        .map(
          (f) =>
            `<div class="finding ${esc(f.severity)}"><span class="pill ${esc(f.severity)}">${esc(severityLabels[f.severity])}</span><div><strong>${esc(f.title)}</strong><p>${esc(f.detail)}</p>${f.certificateId ? `<button class="link" data-goto="${esc(f.certificateId)}">Show certificate</button>` : ""}</div></div>`,
        )
        .join("")
    : `<p class="muted">No findings.</p>`;

  $("chains").innerHTML = a.chains.length
    ? a.chains.map(renderChain).join("")
    : `<p class="muted">Open certificates to build chains.</p>`;

  $("cert-count").textContent = plural(a.certificates.length, "certificate");
  $("certificates").innerHTML = a.certificates.map(renderCertificate).join("");

  $("keys-panel").hidden = a.keys.length === 0;
  $("keys").innerHTML = a.keys
    .map((k) => {
      const cert = a.certificates.find((x) => x.id === k.certificateId);
      return `<div class="key-row"><span class="pill ${k.matched ? "ok" : "error"}">${k.matched ? "Matches" : "No match"}</span><div><strong>${esc(k.description)}</strong><small>From ${esc(k.source)}${cert ? " · belongs to " + esc(cert.subjectName) : " · belongs to no provided certificate"}</small></div></div>`;
    })
    .join("");
}

function renderChain(ch: Chain) {
  const statusTone =
    ch.status === "complete" || ch.status === "root-not-provided"
      ? "ok"
      : ch.status === "issuer-missing"
        ? "warning"
        : "info";
  const links = ch.links
    .map(
      (l, i) =>
        `<li><span class="node ${validityTone(l.validity)}"></span><div><button class="link strong" data-goto="${esc(l.certificateId)}">${esc(l.name)}</button><small>${esc(l.role)} · ${esc(l.validity.replace(/-/g, " "))}</small></div>${i === 0 && ch.keyId ? `<span class="pill ok">key</span>` : ""}</li>`,
    )
    .join("");
  const missing =
    ch.status === "issuer-missing" || ch.status === "root-not-provided"
      ? `<li class="missing"><span class="node"></span><div><span>Issuer not provided</span><small>${ch.status === "issuer-missing" ? "Add the intermediate certificate" : "Usually in the client trust store"}</small></div></li>`
      : "";
  return `<article class="chain"><div class="chain-head"><div><h3>${esc(ch.name)}</h3><p class="${statusTone}-text">${esc(ch.summary)}</p></div><button class="secondary small convert" data-leaf="${esc(ch.leafId)}">Convert…</button></div><ol class="chain-links">${links}${missing}</ol></article>`;
}

function rows(items: [string, string | string[], boolean?][]) {
  return items
    .filter(([, v]) => (Array.isArray(v) ? v.length > 0 : v !== ""))
    .map(
      ([k, v, mono]) =>
        `<tr><th>${esc(k)}</th><td class="${mono ? "mono" : ""}">${Array.isArray(v) ? v.map((x) => `<span class="chip">${esc(x)}</span>`).join("") : esc(v)}${mono ? ` <button class="copy" data-copy="${esc(Array.isArray(v) ? v.join(", ") : v)}" title="Copy">Copy</button>` : ""}</td></tr>`,
    )
    .join("");
}

function renderCertificate(c: Certificate) {
  const tone = validityTone(c.validity);
  return `<details class="cert" id="cert-${esc(c.id)}"><summary><span class="node ${tone}"></span><span class="cert-title"><strong>${esc(c.subjectName)}</strong><small>${esc(c.role)} · issued by ${esc(c.issuerName)}</small></span><span class="pill ${tone}">${esc(validityLabel(c.validity, c.daysRemaining))}</span></summary><table>${rows([
    ["Subject", c.subject],
    ["Issuer", c.issuer],
    ["Valid from", formatDate(c.notBefore)],
    ["Valid until", formatDate(c.notAfter)],
    ["DNS names", c.dnsNames],
    ["IP addresses", c.ipAddresses],
    ["Email addresses", c.emailAddresses],
    ["URIs", c.uris],
    ["Public key", c.keyDescription],
    ["Signature algorithm", c.signatureAlgorithm],
    ["Key usage", c.keyUsage],
    ["Extended key usage", c.extKeyUsage],
    ["Serial number", c.serialNumber, true],
    ["SHA-1 fingerprint", c.sha1, true],
    ["SHA-256 fingerprint", c.sha256, true],
    ["Subject key ID", c.subjectKeyId, true],
    ["Authority key ID", c.authorityKeyId, true],
    ["Found in", c.sources],
  ])}</table></details>`;
}

function openConvert(leafId: string) {
  if (!view) return;
  const cert = view.analysis.certificates.find((c) => c.id === leafId);
  const chain = view.analysis.chains.find((c) => c.leafId === leafId);
  if (!cert || !chain) return;
  convertLeaf = leafId;
  const hasKey = !!chain.keyId;
  $("convert-subject").textContent = `${cert.subjectName} — chain of ${plural(chain.links.length, "certificate")}${hasKey ? ", matching private key loaded" : ", no matching private key loaded"}.`;
  $("targets").innerHTML =
    `<legend>Output format</legend>` +
    availableConversions(hasKey)
      .map(
        (o, i) =>
          `<label class="target${o.disabled ? " disabled" : ""}"><input type="radio" name="target" value="${esc(o.target)}"${i === 0 ? " checked" : ""}${o.disabled ? " disabled" : ""}><span><strong>${esc(o.label)}</strong><small>${esc(o.detail)}${o.disabled ? " Requires the matching private key." : ""}</small></span></label>`,
      )
      .join("");
  $<HTMLInputElement>("pfx-password").value = "";
  $<HTMLInputElement>("pfx-confirm").value = "";
  $("convert-error").textContent = "";
  updateConvertFields();
  $<HTMLDialogElement>("convert-dialog").showModal();
}

function selectedTarget() {
  return (
    document.querySelector<HTMLInputElement>('input[name="target"]:checked')
      ?.value ?? "pem-chain"
  );
}
function updateConvertFields() {
  const t = selectedTarget();
  $("pfx-fields").hidden = t !== "pfx";
  $("key-warning").hidden = t !== "pem-chain-key" && t !== "key-pem";
  $("convert-error").textContent = "";
}

$("targets").addEventListener("change", updateConvertFields);
$("convert-save").addEventListener("click", (e) => {
  e.preventDefault();
  const target = selectedTarget();
  const pw = $<HTMLInputElement>("pfx-password");
  const confirm = $<HTMLInputElement>("pfx-confirm");
  let password = "";
  if (target === "pfx") {
    const problem = pfxPasswordProblem(pw.value, confirm.value);
    if (problem) {
      $("convert-error").textContent = problem;
      return;
    }
    password = pw.value;
  }
  void task("Converting…", async () => {
    try {
      const r = await api().Convert(convertLeaf, target, password);
      if (r.cancelled) return;
      $<HTMLDialogElement>("convert-dialog").close();
      notice(`Saved ${r.filename}. The original files were not changed.`, "ok");
    } catch (err) {
      $("convert-error").textContent = errorText(err);
    } finally {
      pw.value = "";
      confirm.value = "";
      password = "";
    }
  });
});
$("convert-dialog").addEventListener("close", () => {
  $<HTMLInputElement>("pfx-password").value = "";
  $<HTMLInputElement>("pfx-confirm").value = "";
});

const open = () =>
  task("Opening…", async () => {
    notice("");
    apply(await api().OpenFiles());
  });
$("open").addEventListener("click", open);
$("open-empty").addEventListener("click", open);
$("add").addEventListener("click", open);
$("clear").addEventListener("click", () =>
  task("Closing…", async () => {
    notice("");
    apply(await api().Clear());
  }),
);
$<HTMLSelectElement>("soon").addEventListener("change", (e) =>
  task("Checking…", async () =>
    apply(await api().SetExpiringSoonDays(Number((e.target as HTMLSelectElement).value))),
  ),
);
for (const fmt of ["html", "json"]) {
  $("report-" + fmt).addEventListener("click", () =>
    task("Saving report…", async () => {
      const r = await api().ExportReport(fmt);
      if (!r.cancelled) notice(`Saved ${r.filename}. It contains no private keys or passwords.`, "ok");
    }),
  );
}

document.addEventListener("submit", (e) => {
  const form = (e.target as HTMLElement).closest<HTMLFormElement>("form.unlock");
  if (!form) return;
  e.preventDefault();
  const input = form.querySelector("input")!;
  const password = input.value;
  input.value = "";
  void task("Opening PFX…", async () => {
    notice("");
    try {
      apply(await api().Unlock(form.dataset.id!, password));
    } catch (err) {
      const id = form.dataset.id!;
      const v = await api().State();
      apply(v);
      // Wrong passwords are shown next to the file; other problems in the notice bar.
      if (!v.files.find((f) => f.id === id)?.error) notice(errorText(err), "error");
      document
        .querySelector<HTMLInputElement>(`form.unlock[data-id="${CSS.escape(id)}"] input`)
        ?.focus();
    }
  });
});

document.addEventListener("click", (e) => {
  const el = e.target as HTMLElement;
  const remove = el.closest<HTMLButtonElement>("button.remove");
  if (remove)
    return void task("Closing…", async () => apply(await api().RemoveFile(remove.dataset.id!)));
  const convert = el.closest<HTMLButtonElement>("button.convert");
  if (convert) return openConvert(convert.dataset.leaf!);
  const goto = el.closest<HTMLButtonElement>("[data-goto]");
  if (goto) {
    const d = document.getElementById("cert-" + goto.dataset.goto) as HTMLDetailsElement | null;
    if (d) {
      d.open = true;
      d.scrollIntoView({ behavior: "smooth", block: "start" });
      d.classList.add("flash");
      setTimeout(() => d.classList.remove("flash"), 1200);
    }
    return;
  }
  const copy = el.closest<HTMLButtonElement>("button.copy");
  if (copy) {
    const text = copy.dataset.copy ?? "";
    const done = () => {
      copy.textContent = "Copied";
      setTimeout(() => (copy.textContent = "Copy"), 1200);
    };
    (window.runtime?.ClipboardSetText(text) ?? navigator.clipboard.writeText(text)).then(done, () =>
      notice("Cannot copy to the clipboard.", "error"),
    );
  }
});

window.runtime?.OnFileDrop((_x, _y, paths) => {
  void task("Opening…", async () => {
    notice("");
    apply(await api().AddFiles(paths));
  });
}, false);

void (async () => {
  try {
    apply(await api().State());
  } catch (e) {
    notice(errorText(e), "error");
  }
})();
