// Pure presentation helpers, tested with node --test.

export function escapeHTML(value) {
  return String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
}

export const severityLabels = {
  error: "Error",
  warning: "Warning",
  info: "Note",
  ok: "Passed",
};

export function validityLabel(validity, days) {
  switch (validity) {
    case "expired":
      return `Expired ${Math.abs(days)} day${Math.abs(days) === 1 ? "" : "s"} ago`;
    case "not-yet-valid":
      return "Not yet valid";
    case "expiring-soon":
      return `Expires in ${days} day${days === 1 ? "" : "s"}`;
    default:
      return `Valid · ${days} days left`;
  }
}

export function validityTone(validity) {
  return validity === "valid"
    ? "ok"
    : validity === "expiring-soon"
      ? "warning"
      : "error";
}

export function formatDate(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())} UTC`;
}

export function plural(n, word) {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

export const conversions = [
  {
    target: "pem-chain",
    label: "PEM certificate chain",
    detail: "Leaf first, then issuers. For web servers and most tools.",
    needsKey: false,
  },
  {
    target: "der",
    label: "DER certificate (.cer)",
    detail: "The selected certificate only, binary encoding.",
    needsKey: false,
  },
  {
    target: "p7b",
    label: "PKCS#7 chain (.p7b)",
    detail: "Certificates only, for Windows and Java imports.",
    needsKey: false,
  },
  {
    target: "pfx",
    label: "PKCS#12 / PFX with private key",
    detail: "Certificate, issuers and key, protected by a new password (AES-256).",
    needsKey: true,
  },
  {
    target: "pem-chain-key",
    label: "PEM chain + private key",
    detail: "One file with the chain and an UNENCRYPTED private key.",
    needsKey: true,
  },
  {
    target: "key-pem",
    label: "Private key only (.key)",
    detail: "UNENCRYPTED PKCS#8 PEM private key.",
    needsKey: true,
  },
];

export function availableConversions(hasKey) {
  return conversions.map((c) => ({
    ...c,
    disabled: c.needsKey && !hasKey,
  }));
}

export function pfxPasswordProblem(password, confirm) {
  if ([...password].length < 8) return "Use at least 8 characters.";
  if (password !== confirm) return "The passwords do not match.";
  return "";
}

export function sortFiles(files) {
  const order = { password: 0, error: 1, ready: 2 };
  return [...files].sort((a, b) => order[a.state] - order[b.state]);
}
