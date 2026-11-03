import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

/** The X server Reach brings for X11 forwarding on Windows. */
export interface X11ServerStatus {
  /** Reach brings its own X server on this system (Windows). */
  supported: boolean;
  installed: boolean;
  version: string;
}

export interface X11ServerProgress {
  stage: 'download' | 'verify' | 'unpack';
  done: number;
  total: number;
}

export function x11ServerStatus(): Promise<X11ServerStatus> {
  return invoke<X11ServerStatus>('x11server_status');
}

/** Downloads and sets up the X server; rejects with "cancelled" when stopped. */
export function x11ServerInstall(): Promise<void> {
  return invoke('x11server_install');
}

export function x11ServerCancel(): Promise<void> {
  return invoke('x11server_cancel');
}

/** Stops Reach's X server and removes its files. */
export function x11ServerRemove(): Promise<void> {
  return invoke('x11server_remove');
}

export function onX11ServerProgress(cb: (p: X11ServerProgress) => void): Promise<UnlistenFn> {
  return listen<X11ServerProgress>('x11server-progress', (e) => cb(e.payload));
}
