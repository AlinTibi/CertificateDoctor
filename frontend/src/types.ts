export type Severity = "error" | "warning" | "info" | "ok";

export interface Certificate {
  id: string;
  subject: string;
  issuer: string;
  subjectName: string;
  issuerName: string;
  serialNumber: string;
  notBefore: string;
  notAfter: string;
  daysRemaining: number;
  validity: "valid" | "expired" | "not-yet-valid" | "expiring-soon";
  dnsNames: string[];
  ipAddresses: string[];
  emailAddresses: string[];
  uris: string[];
  signatureAlgorithm: string;
  publicKeyAlgorithm: string;
  keySize: number;
  keyDescription: string;
  isCA: boolean;
  selfSigned: boolean;
  role: string;
  keyUsage: string[];
  extKeyUsage: string[];
  subjectKeyId: string;
  authorityKeyId: string;
  sha1: string;
  sha256: string;
  sources: string[];
}

export interface Finding {
  severity: Severity;
  code: string;
  title: string;
  detail: string;
  certificateId?: string;
}

export interface Chain {
  leafId: string;
  name: string;
  links: { certificateId: string; name: string; role: string; validity: string }[];
  status: string;
  summary: string;
  keyId?: string;
}

export interface Key {
  id: string;
  description: string;
  source: string;
  certificateId?: string;
  matched: boolean;
}

export interface Analysis {
  tool: string;
  generatedAt: string;
  expiringSoonDays: number;
  verdict: Severity;
  verdictText: string;
  counts: Partial<Record<Severity, number>>;
  certificates: Certificate[];
  keys: Key[];
  chains: Chain[];
  findings: Finding[];
  limitations: string[];
}

export interface FileView {
  id: string;
  name: string;
  state: "ready" | "password" | "error";
  error: string;
  format: string;
  certificates: number;
  keys: number;
}

export interface View {
  files: FileView[];
  analysis: Analysis;
  expiringSoonDays: number;
  rejected: string[];
}

export interface SaveResult {
  cancelled: boolean;
  filename: string;
}

declare global {
  interface Window {
    go?: {
      main: {
        App: {
          State(): Promise<View>;
          OpenFiles(): Promise<View>;
          AddFiles(paths: string[]): Promise<View>;
          Unlock(id: string, password: string): Promise<View>;
          RemoveFile(id: string): Promise<View>;
          Clear(): Promise<View>;
          SetExpiringSoonDays(days: number): Promise<View>;
          Convert(leafId: string, target: string, password: string): Promise<SaveResult>;
          ExportReport(format: string): Promise<SaveResult>;
        };
      };
    };
    runtime?: {
      OnFileDrop(
        callback: (x: number, y: number, paths: string[]) => void,
        useDropTarget: boolean,
      ): void;
      ClipboardSetText(text: string): Promise<boolean>;
    };
  }
}
