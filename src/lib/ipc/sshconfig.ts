import { invoke } from '@tauri-apps/api/core';
import type { SshOptions } from './sessions';

/** What became of a line (src-tauri/src/ssh/sshconf/resolve.rs `Status`). */
export type LineStatus =
  | { kind: 'applied' }
  | { kind: 'overridden' }
  | { kind: 'inactive' }
  | { kind: 'structure' }
  | { kind: 'error'; detail: string }
  | { kind: 'ignored' }
  | { kind: 'deprecated' }
  | { kind: 'unsupported' };

/** Whether Reach acts on a keyword yet (report.rs `Support`). */
export type Support = 'yes' | 'structure' | 'sessionField' | 'notYet';

/** What the connection did with an applied keyword (apply.rs `Use`). */
export type Use = { kind: 'used' } | { kind: 'partly'; detail: string } | { kind: 'notUsed'; detail: string };

export interface ReportLine {
  at: { file: string; line: number };
  keyword: string;
  text: string;
  status: LineStatus;
  support: Support | null;
  used?: Use;
  weakening?: string;
  command?: string;
}

export interface Weakening {
  keyword: string;
  value: string;
  reason: string;
  accepted: boolean;
}

export interface SshConfigReport {
  host: string;
  lines: ReportLine[];
  weakenings: Weakening[];
  commands: string[];
  refused: string | null;
  errors: string[];
  /** Lines in Host blocks for other hosts, counted but not listed. */
  otherHostLines: number;
}

export interface ImportHop {
  host: string;
  port: number;
  user: string;
  identityFiles: string[];
}

export interface HostImport {
  alias: string;
  hostname: string;
  port: number;
  user: string;
  identityFiles: string[];
  proxyJump: ImportHop[];
  options: SshOptions;
  report: SshConfigReport;
}

export interface SshConfigScan {
  hosts: HostImport[];
  files: string[];
}

/** Every concrete host in ~/.ssh/config (and what it includes), resolved as ssh would. */
export async function sshconfigScan(): Promise<SshConfigScan> {
  return invoke<SshConfigScan>('sshconfig_scan');
}

/** Check if an SSH config file exists. */
export async function sshconfigExists(): Promise<boolean> {
  return invoke<boolean>('sshconfig_exists');
}

/** What a session's ssh_config settings do. */
export async function sshOptionsReport(host: string, port: number, username: string, options: SshOptions): Promise<SshConfigReport> {
  return invoke<SshConfigReport>('ssh_options_report', { host, port, username, options });
}

/** How an approved weakening is stored (apply.rs `weakening_key`). */
export function weakeningKey(w: Pick<Weakening, 'keyword' | 'value'>): string {
  return `${w.keyword} ${w.value}`;
}
