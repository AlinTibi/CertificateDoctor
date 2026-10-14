export function escapeHTML(value: unknown): string;
export const severityLabels: Record<string, string>;
export function validityLabel(validity: string, days: number): string;
export function validityTone(validity: string): "ok" | "warning" | "error";
export function formatDate(iso: string): string;
export function plural(n: number, word: string): string;
export interface Conversion {
  target: string;
  label: string;
  detail: string;
  needsKey: boolean;
}
export const conversions: Conversion[];
export function availableConversions(
  hasKey: boolean,
): (Conversion & { disabled: boolean })[];
export function pfxPasswordProblem(password: string, confirm: string): string;
export function sortFiles<T extends { state: string }>(files: T[]): T[];
