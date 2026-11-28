import {
  getDriveAccessToken,
  getDriveBridgeState,
  fetchDriveQuotaAndProfile,
  promptWorkspaceCapabilitiesUpgrade,
  isMachackabookAccount,
  type DriveQuotaSnapshot,
} from './drivePackageBridge.ts';
import {
  sparseBandEngine,
  SPARSE_BAND_TOTAL_BYTES,
  TOTAL_HYPER_BLOCKS,
  LOGICAL_VOLUME_BYTES,
  SPARSE_FUSION_TIERS,
  type SparseFusionTierId,
} from './sparseBandCryptoEngine.ts';
import { memoryFabric } from './memoryFabric.ts';
import { refreshConvergenceState } from './livingSystemConvergence.ts';
import { creedAdmittanceService } from './creedAdmittance.ts';

export type MountLifecycleState =
  | 'UNMOUNTED'
  | 'DISCOVERING_DRIVE'
  | 'NEEDS_DRIVE_INIT'
  | 'SYNCING_TO_DRIVE'
  | 'MOUNTED_DRIVE_HTTPFS'
  | 'ERROR';

export interface DriveSparseMountStatus {
  lifecycle: MountLifecycleState;
  signedIn: boolean;
  ownerEmail: string;
  ownerDisplayName: string;
  machackabookDetected: boolean;
  driveFolderId: string | null;
  bandsFolderId: string | null;
  manifestFileId: string | null;
  plistFileId: string | null;
  logicalVolumeBytes: number;
  logicalVolumeGiB: number;
  mountedLogicalGiB: number;
  bandSizeBytes: number;
  totalSparseBands: number;
  uploadedDriveBands: number;
  httpfsMounted: boolean;
  mountMode: 'ALL' | 'CLIP_PATH_SELECTIVE';
  activeTiers: SparseFusionTierId[];
  rcloneRemotePath: string;
  quota: DriveQuotaSnapshot | null;
  lastSyncAt: string | null;
  message: string;
}

const SPARSEBUNDLE_FOLDER_NAME = 'GAIA_NEXUS_384GiB.sparsebundle';
const LEGACY_SPARSEBUNDLE_FOLDER_NAME = 'GAIA_NEXUS_192GiB.sparsebundle';
const MIME_FOLDER = 'application/vnd.google-apps.folder';

let sessionHmacKeyHex: string | null = null;

function canonicalJson(obj: unknown): string {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return `[${obj.map(canonicalJson).join(',')}]`;
  const rec = obj as Record<string, unknown>;
  const keys = Object.keys(rec).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(rec[k])}`).join(',')}}`;
}

async function sha256HexBrowser(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function ensureSessionHmacKey(): Promise<string> {
  if (sessionHmacKeyHex) return sessionHmacKeyHex;
  const resp = await fetch('/v1/genesis/session');
  if (!resp.ok) throw new Error('Unable to obtain same-origin Genesis HMAC session key');
  const json = (await resp.json()) as { hmacKey?: string };
  if (!json.hmacKey) throw new Error('Missing Genesis HMAC session key');
  sessionHmacKeyHex = json.hmacKey;
  return sessionHmacKeyHex;
}

async function buildSignedHeaders(
  method: string,
  reqPath: string,
  bodyObj: unknown,
  bearerToken: string
): Promise<Record<string, string>> {
  const keyStr = await ensureSessionHmacKey();
  const ts = String(Date.now());
  const nonce = `${ts}-${Math.random().toString(36).slice(2, 10)}`;
  const bodyDigest = await sha256HexBrowser(canonicalJson(bodyObj || {}));
  const msg = `${method}:${reqPath}:${ts}:${nonce}:${bodyDigest}`;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(keyStr),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(msg));
  const sigHex = Array.from(new Uint8Array(sigBuf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${bearerToken}`,
    'x-gaia-genesis-ts': ts,
    'x-gaia-genesis-nonce': nonce,
    'x-gaia-genesis-sig': sigHex,
  };
}

function formatBytesHuman(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) return 'Unlimited / Unknown';
  const gib = bytes / (1024 * 1024 * 1024);
  if (gib >= 1024) return `${(gib / 1024).toFixed(2)} TiB`;
  if (gib >= 1) return `${gib.toFixed(1)} GiB`;
  return `${(bytes / (1024 * 1024)).toFixed(0)} MiB`;
}

function utf8ToBase64Url(input: string): string {
  const bytes = new TextEncoder().encode(input);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

class DriveSparseMountController {
  private status: DriveSparseMountStatus = {
    lifecycle: 'UNMOUNTED',
    signedIn: false,
    ownerEmail: '',
    ownerDisplayName: '',
    machackabookDetected: false,
    driveFolderId: null,
    bandsFolderId: null,
    manifestFileId: null,
    plistFileId: null,
    logicalVolumeBytes: LOGICAL_VOLUME_BYTES,
    logicalVolumeGiB: 384,
    mountedLogicalGiB: 384,
    bandSizeBytes: SPARSE_BAND_TOTAL_BYTES,
    totalSparseBands: TOTAL_HYPER_BLOCKS,
    uploadedDriveBands: 0,
    httpfsMounted: false,
    mountMode: 'ALL',
    activeTiers: SPARSE_FUSION_TIERS.map((t) => t.id),
    rcloneRemotePath: `gdrive:${SPARSEBUNDLE_FOLDER_NAME}`,
    quota: null,
    lastSyncAt: null,
    message: 'Sign in with Google (or Machackabook) to attach your 384 GiB 8-Sparse-Fusion Drive virtual disk.',
  };

  private pendingConfirmResolver: ((confirmed: boolean) => void) | null = null;
  private isHandlingAuth = false;
  private postAuthBannerDismissed = false;

  public getStatus(): DriveSparseMountStatus {
    return { ...this.status };
  }

  private renderClipPathMatrix(): void {
    const gridEl = document.getElementById('clip-path-tier-grid');
    if (gridEl) {
      gridEl.textContent = '';
      for (const tier of SPARSE_FUSION_TIERS) {
        const active =
          this.status.mountMode === 'ALL' || this.status.activeTiers.includes(tier.id);
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = active
          ? 'text-left px-1.5 py-1 rounded border border-emerald-400/50 bg-emerald-500/15 text-emerald-100 space-y-0.5 transition'
          : 'text-left px-1.5 py-1 rounded border border-slate-700 bg-slate-950/70 text-slate-400 space-y-0.5 opacity-75 transition';
        btn.style.clipPath = active ? 'polygon(0 0, 100% 0, 96% 100%, 0 100%)' : 'polygon(4% 0, 100% 0, 96% 100%, 0 100%)';

        const top = document.createElement('div');
        top.className = 'flex justify-between items-center text-[8px] font-bold tabular-nums';
        top.textContent = `${tier.bitWidth}b · ${tier.logicalGiB}G`;

        const sub = document.createElement('div');
        sub.className = 'text-[7px] truncate opacity-85';
        sub.textContent = tier.label;

        btn.appendChild(top);
        btn.appendChild(sub);
        btn.addEventListener('click', () => {
          void this.toggleFusionTier(tier.id);
        });
        gridEl.appendChild(btn);
      }
    }

    const svgOverlay = document.getElementById('clip-path-fusion-svg');
    if (svgOverlay) {
      for (const tier of SPARSE_FUSION_TIERS) {
        const seg = svgOverlay.querySelector<SVGElement>(`[data-clip-tier="${tier.id}"]`);
        if (seg) {
          const active =
            this.status.mountMode === 'ALL' || this.status.activeTiers.includes(tier.id);
          seg.setAttribute('fill-opacity', active ? '0.68' : '0.12');
          seg.setAttribute('stroke-opacity', active ? '0.95' : '0.25');
        }
      }
    }

    const modeUi = document.getElementById('clip-path-mode-ui');
    if (modeUi) {
      modeUi.textContent = `${this.status.mountMode} · ${this.status.mountedLogicalGiB} / 384 GiB (${this.status.activeTiers.length}/8 tiers)`;
    }
  }

  private renderQuotaAndAccountBadges(): void {
    const quotaEl = document.getElementById('drive-quota-summary-ui');
    if (quotaEl) {
      const q = this.status.quota;
      if (!this.status.signedIn) {
        quotaEl.className = 'text-[8px] text-slate-400 bg-slate-950 px-2 py-1 rounded border border-slate-800';
        quotaEl.textContent = 'Google Drive Quota: Sign in to verify full 384 GiB capacity vs Clip-Path slice.';
      } else if (!q || !q.quotaKnown) {
        quotaEl.className = 'text-[8px] text-amber-300 bg-slate-950 px-2 py-1 rounded border border-amber-500/30';
        quotaEl.textContent = `Checking live Drive storageQuota for ${this.status.ownerEmail}…`;
      } else if (q.unlimitedDriveStorage) {
        quotaEl.className = 'text-[8px] text-emerald-300 bg-slate-950 px-2 py-1 rounded border border-emerald-500/40';
        quotaEl.textContent = `Drive Storage: Unlimited (${formatBytesHuman(q.usageBytes)} used) — Full 384 GiB DB permitted ✓`;
      } else {
        const fitsMsg = q.fitsFull384GiB
          ? 'Fits Full 384 GiB Sparsebundle ✓'
          : 'Below 384 GiB raw limit — Sparse bands & Clip-Path Selective recommended';
        quotaEl.className = q.fitsFull384GiB
          ? 'text-[8px] text-emerald-300 bg-slate-950 px-2 py-1 rounded border border-emerald-500/40 tabular-nums'
          : 'text-[8px] text-amber-300 bg-slate-950 px-2 py-1 rounded border border-amber-500/40 tabular-nums';
        quotaEl.textContent = `Drive Free: ${formatBytesHuman(q.freeBytes)} / ${formatBytesHuman(q.limitBytes)} — ${fitsMsg}`;
      }
    }

    const mackBadge = document.getElementById('machackabook-account-badge');
    if (mackBadge) {
      mackBadge.classList.toggle('hidden', !this.status.machackabookDetected);
      if (this.status.machackabookDetected) {
        mackBadge.textContent = `MACHACKABOOK VERIFIED (${this.status.ownerEmail})`;
      }
    }

    const postAuthBanner = document.getElementById('workspace-postauth-prompt');
    if (postAuthBanner) {
      const show = this.status.signedIn && !this.postAuthBannerDismissed;
      postAuthBanner.classList.toggle('hidden', !show);
      const acctSpan = document.getElementById('workspace-postauth-account');
      if (acctSpan && this.status.signedIn) {
        acctSpan.textContent = `${this.status.ownerDisplayName || this.status.ownerEmail} (${this.status.mountedLogicalGiB} GiB attached)`;
      }
    }
  }

  private async refreshRcloneConfPreview(forceOverwriteEditor = false): Promise<void> {
    const editor = document.getElementById('rclone-conf-editor') as HTMLTextAreaElement | null;
    if (!editor) return;
    if (!forceOverwriteEditor && editor.value.trim().length > 20 && document.activeElement === editor) return;
    try {
      const res = await fetch('/v1/sparsebundle/rclone-conf');
      if (res.ok) {
        editor.value = await res.text();
      }
    } catch {
      // ignore fetch error
    }
  }

  private updateUI(): void {
    const s = this.status;
    const isMounted = s.lifecycle === 'MOUNTED_DRIVE_HTTPFS';

    const pillCls = isMounted
      ? 'text-emerald-300'
      : s.lifecycle === 'ERROR'
        ? 'text-rose-300'
        : s.lifecycle === 'NEEDS_DRIVE_INIT' || s.lifecycle === 'SYNCING_TO_DRIVE'
          ? 'text-amber-300'
          : 'text-slate-400';

    const summaryText = isMounted
      ? `MOUNTED (DRIVE+HTTPFS) · ${s.mountedLogicalGiB}/384 GiB (${s.mountMode}) · ${s.uploadedDriveBands} bands synced (${s.ownerEmail})`
      : s.message;

    for (const id of ['drive-sparse-mount-badge', 'audit-drive-mount-badge']) {
      const el = document.getElementById(id);
      if (el) {
        el.className = `text-[8.5px] font-semibold tabular-nums truncate ${pillCls}`;
        el.textContent = isMounted ? `MOUNTED · ${s.mountedLogicalGiB}G HTTPFS` : s.lifecycle;
      }
    }

    for (const id of ['drive-sparse-mount-detail', 'audit-drive-mount-detail']) {
      const el = document.getElementById(id);
      if (el) el.textContent = summaryText;
    }

    const rcloneBox = document.getElementById('drive-rclone-cmd-ui');
    if (rcloneBox) {
      const origin = window.location.origin;
      rcloneBox.textContent = `rclone mount :http:/v1/sparsebundle/httpfs/${SPARSEBUNDLE_FOLDER_NAME} /mnt/gaia384 --http-url ${origin} --vfs-cache-mode full # path=${s.rcloneRemotePath}`;
    }

    const pathInput = document.getElementById('rclone-remote-path-input') as HTMLInputElement | null;
    if (pathInput && document.activeElement !== pathInput) {
      pathInput.value = s.rcloneRemotePath;
    }

    this.renderClipPathMatrix();
    this.renderQuotaAndAccountBadges();
  }

  private async requestExplicitModalConfirmation(opts: {
    title: string;
    description: string;
    items: string[];
    confirmLabel: string;
  }): Promise<boolean> {
    const modal = document.getElementById('drive-confirm-modal');
    const titleEl = document.getElementById('drive-confirm-title');
    const descEl = document.getElementById('drive-confirm-desc');
    const listEl = document.getElementById('drive-confirm-items');
    const okBtn = document.getElementById('btn-drive-confirm-ok');
    if (!modal || !titleEl || !descEl || !listEl || !okBtn) {
      return false;
    }

    titleEl.textContent = opts.title;
    descEl.textContent = opts.description;
    listEl.textContent = '';
    for (const item of opts.items) {
      const li = document.createElement('li');
      li.className = 'truncate';
      li.textContent = `• ${item}`;
      listEl.appendChild(li);
    }
    okBtn.textContent = opts.confirmLabel;
    modal.classList.remove('hidden');

    return new Promise<boolean>((resolve) => {
      this.pendingConfirmResolver = resolve;
    });
  }

  private resolveConfirmationModal(accepted: boolean): void {
    const modal = document.getElementById('drive-confirm-modal');
    if (modal) modal.classList.add('hidden');
    if (this.pendingConfirmResolver) {
      const fn = this.pendingConfirmResolver;
      this.pendingConfirmResolver = null;
      fn(accepted);
    }
  }

  private async driveJsonFetch(url: string, token: string, init?: RequestInit): Promise<Record<string, unknown>> {
    const res = await fetch(url, {
      ...init,
      headers: {
        ...(init?.headers || {}),
        Authorization: `Bearer ${token}`,
      },
    });
    if (!res.ok) {
      const txt = await res.text().catch(() => '');
      throw new Error(`Google API HTTP ${res.status}: ${txt.slice(0, 140)}`);
    }
    if (res.status === 204) return {};
    return (await res.json()) as Record<string, unknown>;
  }

  private async findDriveFile(
    token: string,
    name: string,
    parentId?: string | null,
    mimeType?: string
  ): Promise<{ id: string; name: string; size?: string } | null> {
    const qParts = [`name = '${name.replace(/'/g, "\\'")}'`, 'trashed = false'];
    if (parentId) qParts.push(`'${parentId}' in parents`);
    if (mimeType) qParts.push(`mimeType = '${mimeType}'`);
    const params = new URLSearchParams({
      q: qParts.join(' and '),
      pageSize: '5',
      fields: 'files(id,name,mimeType,size,modifiedTime)',
    });
    const data = await this.driveJsonFetch(`https://www.googleapis.com/drive/v3/files?${params.toString()}`, token);
    const files = Array.isArray(data.files) ? (data.files as Array<{ id: string; name: string; size?: string }>) : [];
    return files[0] ?? null;
  }

  private async createDriveFolder(token: string, name: string, parentId?: string): Promise<string> {
    const meta: Record<string, unknown> = {
      name,
      mimeType: MIME_FOLDER,
    };
    if (parentId) meta.parents = [parentId];
    const data = await this.driveJsonFetch('https://www.googleapis.com/drive/v3/files?fields=id,name', token, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(meta),
    });
    return String(data.id);
  }

  private async uploadOrUpdateDriveBlob(
    token: string,
    params: {
      existingFileId?: string | null;
      name: string;
      parentId: string;
      mimeType: string;
      body: Uint8Array | string;
    }
  ): Promise<string> {
    const metadata: Record<string, unknown> = params.existingFileId
      ? { name: params.name }
      : { name: params.name, parents: [params.parentId] };

    const boundary = `gaia_sb_${Date.now().toString(16)}`;
    const encoder = new TextEncoder();
    const headerPart = encoder.encode(
      `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(metadata)}\r\n` +
        `--${boundary}\r\nContent-Type: ${params.mimeType}\r\n\r\n`
    );
    const payloadBytes =
      typeof params.body === 'string' ? encoder.encode(params.body) : params.body;
    const footerPart = encoder.encode(`\r\n--${boundary}--`);

    const multipartBody = new Uint8Array(headerPart.length + payloadBytes.length + footerPart.length);
    multipartBody.set(headerPart, 0);
    multipartBody.set(payloadBytes, headerPart.length);
    multipartBody.set(footerPart, headerPart.length + payloadBytes.length);

    const url = params.existingFileId
      ? `https://www.googleapis.com/upload/drive/v3/files/${encodeURIComponent(params.existingFileId)}?uploadType=multipart&fields=id`
      : 'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id';

    const res = await fetch(url, {
      method: params.existingFileId ? 'PATCH' : 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': `multipart/related; boundary=${boundary}`,
      },
      body: multipartBody,
    });
    if (!res.ok) {
      const txt = await res.text().catch(() => '');
      throw new Error(`Drive upload failed (${res.status}): ${txt.slice(0, 140)}`);
    }
    const json = (await res.json()) as { id: string };
    return json.id;
  }

  private buildPlistXml(): string {
    return [
      '<?xml version="1.0" encoding="UTF-8"?>',
      '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
      '<plist version="1.0">',
      '<dict>',
      '  <key>CFBundleInfoDictionaryVersion</key>',
      '  <string>6.0</string>',
      '  <key>band-size</key>',
      `  <integer>${SPARSE_BAND_TOTAL_BYTES}</integer>`,
      '  <key>bundle-backingstore-version</key>',
      '  <integer>1</integer>',
      '  <key>diskimage-bundle-type</key>',
      '  <string>com.apple.diskimage.sparsebundle</string>',
      '  <key>size</key>',
      `  <integer>${LOGICAL_VOLUME_BYTES}</integer>`,
      '  <key>gaia-mounted-gib</key>',
      `  <integer>${this.status.mountedLogicalGiB}</integer>`,
      '  <key>gaia-fusion-mode</key>',
      `  <string>${this.status.mountMode}</string>`,
      '</dict>',
      '</plist>',
    ].join('\n');
  }

  private async mountBandsToHttpfsGateway(token: string): Promise<void> {
    const summary = sparseBandEngine.getSummary();
    const descriptors = sparseBandEngine.getPopulatedBandDescriptors().slice(0, 24);
    const bandsPayload = descriptors.map((d) => ({
      bandHex: d.bandHex,
      faceLabel: d.faceLabel,
      payloadBytesUsed: d.payloadBytesUsed,
      tailBitsUsed: d.tailBitsUsed,
      latestLeafHex: d.latestLeafHex,
      tailString: d.orderedHashTailString.slice(0, 32000),
      payloadJson: JSON.stringify({
        format: 'GAIA_SPARSEBAND_8MIB_V2_384G',
        setIndex: d.setIndex,
        blockIndex: d.blockIndex,
        cells: sparseBandEngine.cells.filter((c) => c.setIndex === d.setIndex && c.blockIndex === d.blockIndex),
      }).slice(0, 250_000),
    }));

    const body = {
      driveFolderId: this.status.driveFolderId,
      bandsFolderId: this.status.bandsFolderId,
      mountMode: this.status.mountMode,
      activeTiers: this.status.activeTiers,
      rcloneRemotePath: this.status.rcloneRemotePath,
      setRootsHex: summary.setRootsHex,
      bands: bandsPayload,
    };

    const headers = await buildSignedHeaders('POST', '/v1/sparsebundle/httpfs/mount', body, token);
    const res = await fetch('/v1/sparsebundle/httpfs/mount', {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const errJson = (await res.json().catch(() => ({}))) as { error?: string };
      throw new Error(errJson.error || `HTTPFS mount failed (HTTP ${res.status})`);
    }
    this.status.httpfsMounted = true;
    await this.refreshRcloneConfPreview(true);
  }

  public async toggleFusionTier(tierId: SparseFusionTierId): Promise<void> {
    sparseBandEngine.toggleClipPathTier(tierId);
    const next = sparseBandEngine.getClipPathMountState();
    this.status.mountMode = next.mountMode;
    this.status.activeTiers = next.activeTiers;
    this.status.mountedLogicalGiB = sparseBandEngine.getMountedLogicalGiB();
    this.updateUI();

    const token = getDriveAccessToken();
    if (token && this.status.httpfsMounted) {
      try {
        await this.mountBandsToHttpfsGateway(token);
      } catch {
        // leave UI updated even if HTTPFS update deferred
      }
    }
  }

  public async mountAllFusionTiers(): Promise<void> {
    sparseBandEngine.mountAllFusionTiers();
    const next = sparseBandEngine.getClipPathMountState();
    this.status.mountMode = next.mountMode;
    this.status.activeTiers = next.activeTiers;
    this.status.mountedLogicalGiB = 384;
    this.updateUI();

    const token = getDriveAccessToken();
    if (token && this.status.signedIn) {
      await this.mountBandsToHttpfsGateway(token).catch(() => {});
    }
  }

  public parseAndApplyRcloneConf(rawConf: string): { ok: boolean; message: string } {
    const sanitizedLines: string[] = [];
    let detectedRemote = '';
    let detectedPath = '';
    let detectedFolderId = '';
    let tokenRedacted = false;

    for (const line of rawConf.replace(/\r/g, '').split('\n')) {
      const trimmed = line.trim();
      const secMatch = /^\[([^\]]+)\]$/.exec(trimmed);
      if (secMatch && !detectedRemote) {
        detectedRemote = secMatch[1];
      }
      if (/^token\s*=/.test(trimmed) && !trimmed.includes('<SUPPLIED_AT_RUNTIME')) {
        sanitizedLines.push('token = <SUPPLIED_AT_RUNTIME_FROM_GDRIVE_SESSION>');
        tokenRedacted = true;
        continue;
      }
      const dbMatch = /^(?:database_path|mount_path|path)\s*=\s*(.+)$/i.exec(trimmed);
      if (dbMatch && dbMatch[1].trim()) {
        detectedPath = dbMatch[1].trim();
      }
      const folderMatch = /^root_folder_id\s*=\s*([a-zA-Z0-9_-]{8,128})$/i.exec(trimmed);
      if (folderMatch) {
        detectedFolderId = folderMatch[1].trim();
      }
      sanitizedLines.push(line);
    }

    if (detectedPath) {
      this.status.rcloneRemotePath = detectedPath;
    } else if (detectedRemote) {
      this.status.rcloneRemotePath = `${detectedRemote}:${SPARSEBUNDLE_FOLDER_NAME}`;
    }
    if (detectedFolderId) {
      this.status.driveFolderId = detectedFolderId;
    }

    const editor = document.getElementById('rclone-conf-editor') as HTMLTextAreaElement | null;
    if (editor && tokenRedacted) {
      editor.value = sanitizedLines.join('\n');
    }

    this.updateUI();
    const token = getDriveAccessToken();
    if (token && this.status.httpfsMounted) {
      void this.mountBandsToHttpfsGateway(token);
    }

    return {
      ok: true,
      message: `Loaded rclone.conf -> path="${this.status.rcloneRemotePath}"${tokenRedacted ? ' (embedded token sanitized for security)' : ''}`,
    };
  }

  /**
   * Read-only discovery triggered automatically when the user signs in with Google.
   * Checks storageQuota, detects Machackabook, locates existing .sparsebundle & attaches HTTPFS.
   */
  public async discoverAndAttachOnLogin(): Promise<void> {
    if (this.isHandlingAuth) return;
    const bridge = getDriveBridgeState();
    const token = getDriveAccessToken();
    if (!bridge.signedIn || !token) {
      await this.unmountOnExit(false);
      return;
    }

    this.isHandlingAuth = true;
    this.postAuthBannerDismissed = false;
    this.status.signedIn = true;
    this.status.ownerEmail = bridge.email;
    this.status.ownerDisplayName = bridge.displayName || bridge.email;
    this.status.machackabookDetected = isMachackabookAccount(bridge.email, bridge.displayName);
    this.status.lifecycle = 'DISCOVERING_DRIVE';
    this.status.message = `Signed in as ${bridge.email} — checking Google Drive quota & 384 GiB sparsebundle…`;
    this.updateUI();

    try {
      const quota = bridge.quota || (await fetchDriveQuotaAndProfile(token));
      this.status.quota = quota;

      // Auto-tune selective clip-path mask if Drive quota has a finite ceiling under 384 GiB
      if (quota && quota.quotaKnown && !quota.unlimitedDriveStorage && !quota.fitsFull384GiB) {
        sparseBandEngine.setClipPathMountTiers(['BIT_64', 'BIT_128', 'SOLVENT_EQUATOR', 'ELGAMAL_L10']);
      } else {
        sparseBandEngine.mountAllFusionTiers();
      }
      const cp = sparseBandEngine.getClipPathMountState();
      this.status.mountMode = cp.mountMode;
      this.status.activeTiers = cp.activeTiers;
      this.status.mountedLogicalGiB = sparseBandEngine.getMountedLogicalGiB();

      let rootFolder = await this.findDriveFile(token, SPARSEBUNDLE_FOLDER_NAME, null, MIME_FOLDER);
      if (!rootFolder) {
        rootFolder = await this.findDriveFile(token, LEGACY_SPARSEBUNDLE_FOLDER_NAME, null, MIME_FOLDER);
      }

      if (!rootFolder) {
        await this.mountBandsToHttpfsGateway(token);
        this.status.lifecycle = 'NEEDS_DRIVE_INIT';
        this.status.driveFolderId = null;
        this.status.bandsFolderId = null;
        this.status.message = `HTTPFS attached (${this.status.mountedLogicalGiB}/384 GiB). Click SYNC 384GiB TO DRIVE to save sparse bands to ${bridge.email}'s Drive.`;
        this.updateUI();
        return;
      }

      this.status.driveFolderId = rootFolder.id;
      const bandsFolder = await this.findDriveFile(token, 'bands', rootFolder.id, MIME_FOLDER);
      this.status.bandsFolderId = bandsFolder?.id ?? null;

      const manifestFile = await this.findDriveFile(token, 'GAIA_MANIFEST.json', rootFolder.id);
      this.status.manifestFileId = manifestFile?.id ?? null;
      const plistFile = await this.findDriveFile(token, 'Info.plist', rootFolder.id);
      this.status.plistFileId = plistFile?.id ?? null;

      let hydratedCount = 0;
      if (manifestFile?.id) {
        const rawRes = await fetch(
          `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(manifestFile.id)}?alt=media`,
          { headers: { Authorization: `Bearer ${token}` } }
        );
        if (rawRes.ok) {
          const manifest = (await rawRes.json()) as {
            cells?: Array<{ sheetName: string; row: number; col: number; rawValue: string }>;
          };
          if (Array.isArray(manifest.cells) && manifest.cells.length > 0) {
            hydratedCount = sparseBandEngine.hydrateMountedCells(manifest.cells);
          }
        }
      }

      let remoteBandCount = 0;
      if (bandsFolder?.id) {
        const listParams = new URLSearchParams({
          q: `'${bandsFolder.id}' in parents and trashed = false`,
          pageSize: '100',
          fields: 'files(id,name,size)',
        });
        const listData = await this.driveJsonFetch(
          `https://www.googleapis.com/drive/v3/files?${listParams.toString()}`,
          token
        );
        remoteBandCount = Array.isArray(listData.files) ? listData.files.length : 0;
      }

      await this.mountBandsToHttpfsGateway(token);
      this.status.uploadedDriveBands = remoteBandCount;
      this.status.lifecycle = 'MOUNTED_DRIVE_HTTPFS';
      this.status.lastSyncAt = new Date().toISOString();
      this.status.message = `Attached ${rootFolder.name} from ${bridge.email} (${remoteBandCount} Drive bands, +${hydratedCount} hydrated cells, ${this.status.mountedLogicalGiB}/384 GiB).`;

      const sum = sparseBandEngine.getSummary();
      const firstCell = sparseBandEngine.cells[0];
      if (firstCell) {
        memoryFabric.recordSparseBandEvent({
          operation: 'SPARSE_BAND_INGEST',
          sourceModule: `DriveMount:${bridge.email}`,
          blockIndex: firstCell.blockIndex,
          merkleRoot: sum.setRootsHex[0],
          activeMerkleNodes: sum.merkleNodesPerSet,
          blake2b512Hex: firstCell.blake2b512Hex,
          blake2b128Hex: firstCell.blake2b128Hex,
          sha256dHex: firstCell.sha256dHex,
          deweyAddress: firstCell.deweyAddress,
          coprimeLaneId: firstCell.laneId,
          orbIndex: firstCell.orbIndex,
          sparseBandOffset: firstCell.byteOffset,
          prismsEncodedDelta: hydratedCount,
        });
        refreshConvergenceState(true);
      }
      this.updateUI();
    } catch (err) {
      this.status.lifecycle = 'ERROR';
      this.status.message = err instanceof Error ? err.message : 'Drive mount discovery failed';
      this.updateUI();
    } finally {
      this.isHandlingAuth = false;
    }
  }

  public async syncSparseBundleToDrive(): Promise<boolean> {
    const bridge = getDriveBridgeState();
    const token = getDriveAccessToken();
    if (!bridge.signedIn || !token) {
      this.status.lifecycle = 'ERROR';
      this.status.message = 'Sign in with Google first to sync your 384 GiB sparsebundle to Google Drive.';
      this.updateUI();
      return false;
    }

    const descriptors = sparseBandEngine.getPopulatedBandDescriptors().slice(0, 4);
    const qNote = this.status.quota?.fitsFull384GiB
      ? 'Google Drive quota verified sufficient for sparse volume metadata & bands.'
      : 'Note: Using sparse allocation + 8-Sparse-Fusion Clip-Path bands to fit within Drive quota.';

    const affectedItems = [
      qNote,
      `${SPARSEBUNDLE_FOLDER_NAME}/ (Google Drive root folder)`,
      `Info.plist (384 GiB = ${LOGICAL_VOLUME_BYTES.toLocaleString()} B · Mode ${this.status.mountMode})`,
      'mount.token.json (signed-in session attach lease, zero secrets)',
      `GAIA_MANIFEST.json (${sparseBandEngine.cells.length} verified BLAKE2b+SHA256d cells)`,
      ...descriptors.map(
        (d) => `bands/${d.bandHex} (8,388,608-byte 8 MiB sparse band · Set ${d.setIndex + 1} Blk #${d.blockIndex})`
      ),
    ];

    const confirmed = await this.requestExplicitModalConfirmation({
      title: 'Confirm Google Drive 384 GiB Sparsebundle Sync',
      description: `Upload and update ${affectedItems.length} items inside Google Drive for ${bridge.email}?`,
      items: affectedItems,
      confirmLabel: 'CONFIRM DRIVE UPLOAD',
    });

    if (!confirmed) {
      this.status.message = 'Google Drive sync cancelled (no Drive files were modified).';
      this.updateUI();
      return false;
    }

    this.status.lifecycle = 'SYNCING_TO_DRIVE';
    this.status.message = `Syncing Info.plist, manifest & ${descriptors.length} × 8 MiB sparse bands to Google Drive…`;
    this.updateUI();

    try {
      let folderId = this.status.driveFolderId;
      if (!folderId) {
        const found = await this.findDriveFile(token, SPARSEBUNDLE_FOLDER_NAME, null, MIME_FOLDER);
        folderId = found?.id ?? (await this.createDriveFolder(token, SPARSEBUNDLE_FOLDER_NAME));
        this.status.driveFolderId = folderId;
      }

      let bandsId = this.status.bandsFolderId;
      if (!bandsId) {
        const foundBands = await this.findDriveFile(token, 'bands', folderId, MIME_FOLDER);
        bandsId = foundBands?.id ?? (await this.createDriveFolder(token, 'bands', folderId));
        this.status.bandsFolderId = bandsId;
      }

      const existingPlist = await this.findDriveFile(token, 'Info.plist', folderId);
      this.status.plistFileId = await this.uploadOrUpdateDriveBlob(token, {
        existingFileId: existingPlist?.id,
        name: 'Info.plist',
        parentId: folderId,
        mimeType: 'application/xml',
        body: this.buildPlistXml(),
      });

      const tokenDoc = JSON.stringify(
        {
          status: 'MOUNTED',
          ownerEmail: bridge.email,
          logicalVolumeBytes: LOGICAL_VOLUME_BYTES,
          logicalVolumeGiB: 384,
          mountedLogicalGiB: this.status.mountedLogicalGiB,
          mountMode: this.status.mountMode,
          activeTiers: this.status.activeTiers,
          bandSizeBytes: SPARSE_BAND_TOTAL_BYTES,
          totalSparseBands: TOTAL_HYPER_BLOCKS,
          setRootsHex: sparseBandEngine.getSummary().setRootsHex,
          mountedAt: new Date().toISOString(),
        },
        null,
        2
      );
      const existingTokenFile = await this.findDriveFile(token, 'mount.token.json', folderId);
      await this.uploadOrUpdateDriveBlob(token, {
        existingFileId: existingTokenFile?.id,
        name: 'mount.token.json',
        parentId: folderId,
        mimeType: 'application/json',
        body: tokenDoc,
      });

      const manifestDoc = JSON.stringify({
        schema: 'GAIA_384GIB_SPARSEBUNDLE_V2',
        updatedAt: new Date().toISOString(),
        summary: sparseBandEngine.getSummary(),
        cells: sparseBandEngine.cells.slice(-512).map((c) => ({
          sheetName: c.sheetName,
          row: c.row,
          col: c.col,
          rawValue: c.rawValue,
          deweyAddress: c.deweyAddress,
          blake2b128Hex: c.blake2b128Hex,
          sha256dHex: c.sha256dHex,
          receiptWord: c.receiptWord,
          prismRgbHex: c.prismRgbHex,
        })),
      });
      const existingManifest = await this.findDriveFile(token, 'GAIA_MANIFEST.json', folderId);
      this.status.manifestFileId = await this.uploadOrUpdateDriveBlob(token, {
        existingFileId: existingManifest?.id,
        name: 'GAIA_MANIFEST.json',
        parentId: folderId,
        mimeType: 'application/json',
        body: manifestDoc,
      });

      let uploadedCount = 0;
      for (const desc of descriptors) {
        const bandBytes = sparseBandEngine.materializeBandBinary(desc.setIndex, desc.blockIndex);
        const existingBand = await this.findDriveFile(token, desc.bandHex, bandsId);
        await this.uploadOrUpdateDriveBlob(token, {
          existingFileId: existingBand?.id,
          name: desc.bandHex,
          parentId: bandsId,
          mimeType: 'application/octet-stream',
          body: bandBytes,
        });
        uploadedCount++;
        this.status.message = `Uploaded 8 MiB band ${desc.bandHex} (${uploadedCount}/${descriptors.length}) to Google Drive…`;
        this.updateUI();
      }

      await this.mountBandsToHttpfsGateway(token);
      this.status.uploadedDriveBands = uploadedCount;
      this.status.lifecycle = 'MOUNTED_DRIVE_HTTPFS';
      this.status.lastSyncAt = new Date().toISOString();
      this.status.message = `Mounted & synced ${uploadedCount} × 8 MiB sparse bands (${bridge.email}) via Drive + HTTPFS.`;
      this.updateUI();

      creedAdmittanceService.evaluateOperation({
        functionId: 'fn:drive.mountSparseBundle',
        functionName: 'driveSparseMount.syncSparseBundleToDrive',
        branchId: 'BRANCH-MEMORY-WRITE',
        category: 'MEMORY_WRITE',
        required: false,
        predicates: {
          authorization: { state: 'PASS', reason: `Explicitly confirmed Drive upload for ${bridge.email}` },
          capacity: { state: 'PASS', reason: `${uploadedCount} × 8 MiB bands + 384 GiB Info.plist synced` },
          verification: { state: 'PASS', reason: `Folder ${folderId} bound to HTTPFS gateway` },
          boundary: { state: 'PASS', reason: 'Capped per-sync band batch with in-memory Bearer auth' },
          provenancePrivacy: { state: 'PASS', reason: 'User confirmation enforced prior to Drive mutation' },
        },
      });
      return true;
    } catch (err) {
      this.status.lifecycle = 'ERROR';
      this.status.message = err instanceof Error ? err.message : 'Google Drive sparsebundle sync failed';
      this.updateUI();
      return false;
    }
  }

  public async unmountOnExit(keepalive = false): Promise<void> {
    try {
      await fetch('/v1/sparsebundle/httpfs/unmount', {
        method: 'POST',
        keepalive,
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
    } catch (_) {}

    const bridge = getDriveBridgeState();
    this.status.httpfsMounted = false;
    this.status.signedIn = bridge.signedIn;
    this.status.ownerEmail = bridge.email;
    this.status.ownerDisplayName = bridge.displayName || bridge.email;
    this.status.machackabookDetected = bridge.machackabookDetected;
    this.status.quota = bridge.quota;
    this.status.lifecycle = 'UNMOUNTED';
    this.status.message = bridge.signedIn
      ? `HTTPFS unmounted cleanly for ${bridge.email}.`
      : 'Signed out — virtual 384 GiB HTTPFS mount released.';
    this.updateUI();
  }

  public downloadRcloneHelperBundle(): void {
    const origin = window.location.origin;
    const scriptText = [
      '#!/usr/bin/env bash',
      '# GAIA NEXUS 384 GiB 8-Sparse-Fusion HTTPFS & Google Drive rclone Mount Helper',
      `# Volume Size: 384 GiB (${LOGICAL_VOLUME_BYTES} bytes = ${TOTAL_HYPER_BLOCKS} x 8 MiB sparse bands)`,
      `# Clip-Path Mode: ${this.status.mountMode} (${this.status.mountedLogicalGiB} GiB)`,
      'set -euo pipefail',
      '',
      'MOUNT_POINT="${1:-$HOME/mnt/gaia_384gib}"',
      'mkdir -p "$MOUNT_POINT"',
      '',
      '# Option A: Mount live HTTPFS virtual 384 GiB disk served by this app:',
      `rclone mount :http:/v1/sparsebundle/httpfs/${SPARSEBUNDLE_FOLDER_NAME} "$MOUNT_POINT" \\`,
      `  --http-url "${origin}" \\`,
      '  --vfs-cache-mode full \\',
      '  --read-only',
      '',
      '# Option B: Mount directly using your sanitized rclone.conf remote:',
      `# rclone mount --config ./rclone.conf "${this.status.rcloneRemotePath}" "$MOUNT_POINT" --vfs-cache-mode writes`,
      '',
    ].join('\n');

    const blob = new Blob([scriptText], { type: 'text/x-shellscript' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'mount_384gib_sparsebundle.sh';
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1500);
  }

  public async downloadSanitizedRcloneConf(): Promise<void> {
    const editor = document.getElementById('rclone-conf-editor') as HTMLTextAreaElement | null;
    let text = editor?.value?.trim() || '';
    if (!text) {
      const res = await fetch('/v1/sparsebundle/rclone-conf');
      text = res.ok ? await res.text() : '';
    }
    const clean = text.replace(/^token\s*=.*$/gm, 'token = <SUPPLIED_AT_RUNTIME_FROM_GDRIVE_SESSION>');
    const blob = new Blob([clean], { type: 'text/plain;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'rclone.conf';
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1500);
  }

  private renderWorkspaceOutput(lines: Array<{ label: string; text: string; url?: string; tone?: 'ok' | 'warn' | 'err' }>): void {
    const host = document.getElementById('workspace-docs-meet-output');
    if (!host) return;
    host.textContent = '';
    for (const item of lines) {
      const row = document.createElement('div');
      row.className = 'bg-slate-950 px-2 py-1 rounded border border-slate-800 space-y-0.5 text-[8.5px]';
      const head = document.createElement('div');
      head.className =
        item.tone === 'err'
          ? 'text-rose-300 font-semibold'
          : item.tone === 'warn'
            ? 'text-amber-300 font-semibold'
            : 'text-emerald-300 font-semibold';
      head.textContent = item.label;
      const body = document.createElement('div');
      body.className = 'text-slate-300 break-words';
      body.textContent = item.text;
      row.appendChild(head);
      row.appendChild(body);
      if (item.url && /^https:\/\/(meet|docs|sheets|slides|calendar|mail)\.google\.com\//.test(item.url)) {
        const a = document.createElement('a');
        a.href = item.url;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        a.className = 'inline-block text-sky-300 underline hover:text-sky-200 mt-0.5';
        a.textContent = item.url;
        row.appendChild(a);
      }
      host.appendChild(row);
    }
  }

  public async readAndIngestGoogleDocs(): Promise<void> {
    const bridge = getDriveBridgeState();
    const token = getDriveAccessToken();
    if (!bridge.signedIn || !token) {
      this.renderWorkspaceOutput([{ label: 'GOOGLE DOCS', text: 'Sign in with Google to browse and ingest Google Docs.', tone: 'warn' }]);
      return;
    }

    try {
      const params = new URLSearchParams({
        q: "mimeType = 'application/vnd.google-apps.document' and trashed = false",
        pageSize: '5',
        fields: 'files(id,name,modifiedTime,webViewLink)',
      });
      const listData = await this.driveJsonFetch(`https://www.googleapis.com/drive/v3/files?${params.toString()}`, token);
      const docsList = Array.isArray(listData.files)
        ? (listData.files as Array<{ id: string; name: string; webViewLink?: string }>)
        : [];
      if (docsList.length === 0) {
        this.renderWorkspaceOutput([{ label: 'GOOGLE DOCS', text: `No Google Docs found for ${bridge.email}.`, tone: 'warn' }]);
        return;
      }

      const firstDoc = docsList[0];
      const docJson = (await this.driveJsonFetch(
        `https://docs.googleapis.com/v1/documents/${encodeURIComponent(firstDoc.id)}`,
        token
      )) as {
        title?: string;
        body?: { content?: Array<{ paragraph?: { elements?: Array<{ textRun?: { content?: string } }> } }> };
      };

      const lines: string[] = [];
      for (const el of docJson.body?.content ?? []) {
        const txt = (el.paragraph?.elements ?? [])
          .map((e) => e.textRun?.content ?? '')
          .join('')
          .trim();
        if (txt) lines.push(`${docJson.title || firstDoc.name},${txt.slice(0, 120).replace(/,/g, ';')}`);
      }
      const csvPayload = lines.length > 0 ? lines.slice(0, 24).join('\n') : `${firstDoc.name},EMPTY_DOC`;
      const ingested = sparseBandEngine.ingestSpreadsheetDocument(`GDOC_${firstDoc.name}`, csvPayload);

      this.renderWorkspaceOutput([
        {
          label: `DOC READ & INDEXED (${docsList.length} Docs found)`,
          text: `"${docJson.title || firstDoc.name}" -> ${ingested.insertedCells.length} BLAKE2b+SHA256d cells packed (Dewey ${ingested.insertedCells[0]?.deweyAddress ?? '--'}).`,
          url: firstDoc.webViewLink,
          tone: 'ok',
        },
      ]);
      refreshConvergenceState(true);
    } catch (err) {
      this.renderWorkspaceOutput([
        { label: 'GOOGLE DOCS ERROR', text: err instanceof Error ? err.message : 'Unable to read Google Docs', tone: 'err' },
      ]);
    }
  }

  public async createAuditReceiptGoogleDoc(): Promise<void> {
    const bridge = getDriveBridgeState();
    const token = getDriveAccessToken();
    if (!bridge.signedIn || !token) {
      this.renderWorkspaceOutput([{ label: 'GOOGLE DOCS', text: 'Sign in with Google to create a Sparsebundle Audit Doc.', tone: 'warn' }]);
      return;
    }

    const summary = sparseBandEngine.getSummary();
    const docTitle = `GAIA 384GiB Sparsebundle Audit (${new Date().toISOString().slice(0, 16)})`;
    const confirmed = await this.requestExplicitModalConfirmation({
      title: 'Confirm Google Doc Creation',
      description: `Create a new Google Doc in ${bridge.email}'s account summarizing live 384 GiB sparsebundle Merkle roots and Dewey cells?`,
      items: [
        `Document Title: ${docTitle}`,
        `Set1/2/3 Merkle Roots (${summary.populatedCellsCount} indexed cells)`,
      ],
      confirmLabel: 'CREATE GOOGLE DOC',
    });
    if (!confirmed) {
      this.renderWorkspaceOutput([{ label: 'GOOGLE DOCS', text: 'Document creation cancelled.', tone: 'warn' }]);
      return;
    }

    try {
      const created = (await this.driveJsonFetch('https://docs.googleapis.com/v1/documents', token, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: docTitle }),
      })) as { documentId: string; title: string };

      const contentText = [
        `GAIA NEXUS 384 GiB 8-Sparse-Fusion & BLAKE2b Merkle Receipt`,
        `Signed-in Owner: ${bridge.email}`,
        `Logical Capacity: 384 GiB (${LOGICAL_VOLUME_BYTES.toLocaleString()} bytes across ${TOTAL_HYPER_BLOCKS.toLocaleString()} x 8 MiB bands)`,
        `Set 1 Merkle Root: ${summary.setRootsHex[0]}`,
        `Set 2 Merkle Root: ${summary.setRootsHex[1]}`,
        `Set 3 Merkle Root: ${summary.setRootsHex[2]}`,
        `Cyclic Phase: ${summary.cyclicPhaseMode} | Indexed Cells: ${summary.populatedCellsCount}`,
        '',
      ].join('\n');

      await this.driveJsonFetch(
        `https://docs.googleapis.com/v1/documents/${encodeURIComponent(created.documentId)}:batchUpdate`,
        token,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            requests: [{ insertText: { location: { index: 1 }, text: contentText } }],
          }),
        }
      );

      this.renderWorkspaceOutput([
        {
          label: 'GOOGLE DOC CREATED',
          text: `Saved "${created.title}" with live Set1/2/3 Merkle roots.`,
          url: `https://docs.google.com/document/d/${encodeURIComponent(created.documentId)}/edit`,
          tone: 'ok',
        },
      ]);
    } catch (err) {
      this.renderWorkspaceOutput([
        { label: 'GOOGLE DOCS WRITE ERROR', text: err instanceof Error ? err.message : 'Unable to create Google Doc', tone: 'err' },
      ]);
    }
  }

  public async createVerifiedMeetSpace(): Promise<void> {
    const bridge = getDriveBridgeState();
    const token = getDriveAccessToken();
    if (!bridge.signedIn || !token) {
      this.renderWorkspaceOutput([{ label: 'GOOGLE MEET', text: 'Sign in with Google to create a Google Meet space.', tone: 'warn' }]);
      return;
    }

    const confirmed = await this.requestExplicitModalConfirmation({
      title: 'Confirm Google Meet Space Creation',
      description: `Create a new Google Meet conference space under ${bridge.email}?`,
      items: ['New Google Meet room (meet.googleapis.com/v2/spaces)', `Attached session: ${this.status.lifecycle}`],
      confirmLabel: 'CREATE MEET SPACE',
    });
    if (!confirmed) {
      this.renderWorkspaceOutput([{ label: 'GOOGLE MEET', text: 'Meet space creation cancelled.', tone: 'warn' }]);
      return;
    }

    try {
      const space = (await this.driveJsonFetch('https://meet.googleapis.com/v2/spaces', token, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      })) as { name?: string; meetingUri?: string; meetingCode?: string };

      this.renderWorkspaceOutput([
        {
          label: 'GOOGLE MEET SPACE CREATED',
          text: `Code: ${space.meetingCode || space.name || 'ACTIVE'}`,
          url: space.meetingUri,
          tone: 'ok',
        },
      ]);
    } catch (err) {
      this.renderWorkspaceOutput([
        { label: 'GOOGLE MEET ERROR', text: err instanceof Error ? err.message : 'Unable to create Meet space', tone: 'err' },
      ]);
    }
  }

  public async listMeetConferenceRecords(): Promise<void> {
    const bridge = getDriveBridgeState();
    const token = getDriveAccessToken();
    if (!bridge.signedIn || !token) {
      this.renderWorkspaceOutput([{ label: 'GOOGLE MEET', text: 'Sign in with Google to view Meet conference records.', tone: 'warn' }]);
      return;
    }

    try {
      const data = await this.driveJsonFetch('https://meet.googleapis.com/v2/conferenceRecords?pageSize=5', token);
      const records = Array.isArray(data.conferenceRecords)
        ? (data.conferenceRecords as Array<{ name?: string; startTime?: string; endTime?: string }>)
        : [];
      if (records.length === 0) {
        this.renderWorkspaceOutput([{ label: 'GOOGLE MEET RECORDS', text: `No recent conference records found for ${bridge.email}.`, tone: 'warn' }]);
        return;
      }
      this.renderWorkspaceOutput(
        records.map((r) => ({
          label: `MEET RECORD`,
          text: `${r.name || 'conference'} · Started ${r.startTime || '--'}`,
          tone: 'ok' as const,
        }))
      );
    } catch (err) {
      this.renderWorkspaceOutput([
        { label: 'GOOGLE MEET ERROR', text: err instanceof Error ? err.message : 'Unable to fetch conference records', tone: 'err' },
      ]);
    }
  }

  public async exportSparseBandsToGoogleSheet(): Promise<void> {
    const bridge = getDriveBridgeState();
    const token = getDriveAccessToken();
    if (!bridge.signedIn || !token) {
      this.renderWorkspaceOutput([{ label: 'GOOGLE SHEETS', text: 'Sign in with Google to export Sparseband ledger to Sheets.', tone: 'warn' }]);
      return;
    }

    const title = `GAIA 384GiB Solvent Matrix (${new Date().toISOString().slice(0, 16)})`;
    const rows = sparseBandEngine.cells.slice(-30).map((c) => [
      `Set${c.setIndex + 1}`,
      String(c.blockIndex),
      c.deweyAddress,
      c.receiptWord,
      c.prismRgbHex,
      c.blake2b128Hex,
      c.sha256dHex.slice(0, 24),
    ]);

    const confirmed = await this.requestExplicitModalConfirmation({
      title: 'Confirm Google Sheets Export',
      description: `Create a new Google Sheet "${title}" and append ${rows.length} verified Solvent/Sparseband rows?`,
      items: ['sheets.googleapis.com/v4/spreadsheets', `Rows to write: ${rows.length} (Header + Solvent hue/word receipts)`],
      confirmLabel: 'EXPORT TO SHEETS',
    });
    if (!confirmed) return;

    try {
      const sheet = (await this.driveJsonFetch('https://sheets.googleapis.com/v4/spreadsheets', token, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ properties: { title } }),
      })) as { spreadsheetId: string; spreadsheetUrl?: string };

      const values = [
        ['Set', 'BlockIndex', 'DeweyAddress', 'SolventWord', 'PrismHex', 'BLAKE2b_128', 'SHA256d_Prefix'],
        ...rows,
      ];
      await this.driveJsonFetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(sheet.spreadsheetId)}/values/A1:G${values.length}:append?valueInputOption=USER_ENTERED`,
        token,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ values }),
        }
      );

      this.renderWorkspaceOutput([
        {
          label: 'GOOGLE SHEET EXPORTED',
          text: `Saved ${rows.length} Sparseband + Solvent receipts to "${title}".`,
          url: sheet.spreadsheetUrl,
          tone: 'ok',
        },
      ]);
    } catch (err) {
      this.renderWorkspaceOutput([
        { label: 'GOOGLE SHEETS ERROR', text: err instanceof Error ? err.message : 'Unable to export Sheet', tone: 'err' },
      ]);
    }
  }

  public async readAndIngestGoogleSheet(): Promise<void> {
    const bridge = getDriveBridgeState();
    const token = getDriveAccessToken();
    if (!bridge.signedIn || !token) {
      this.renderWorkspaceOutput([{ label: 'GOOGLE SHEETS', text: 'Sign in with Google to ingest a Sheet into Sparseband Prisms.', tone: 'warn' }]);
      return;
    }

    try {
      const params = new URLSearchParams({
        q: "mimeType = 'application/vnd.google-apps.spreadsheet' and trashed = false",
        pageSize: '5',
        fields: 'files(id,name,webViewLink)',
      });
      const listData = await this.driveJsonFetch(`https://www.googleapis.com/drive/v3/files?${params.toString()}`, token);
      const sheets = Array.isArray(listData.files)
        ? (listData.files as Array<{ id: string; name: string; webViewLink?: string }>)
        : [];
      if (sheets.length === 0) {
        this.renderWorkspaceOutput([{ label: 'GOOGLE SHEETS', text: `No Google Sheets found for ${bridge.email}.`, tone: 'warn' }]);
        return;
      }
      const target = sheets[0];
      const valData = (await this.driveJsonFetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(target.id)}/values/A1:H25`,
        token
      )) as { values?: string[][] };
      const csvRows = (valData.values || [])
        .map((r) => r.map((c) => String(c || '').replace(/,/g, ';')).join(','))
        .filter(Boolean);
      const csv = csvRows.length > 0 ? csvRows.join('\n') : `${target.name},EMPTY_SHEET`;
      const ingested = sparseBandEngine.ingestSpreadsheetDocument(`GSHEET_${target.name}`, csv);

      this.renderWorkspaceOutput([
        {
          label: `GOOGLE SHEET INGESTED (${sheets.length} Sheets)`,
          text: `"${target.name}" -> ${ingested.insertedCells.length} cells hashed into 8 MiB bands.`,
          url: target.webViewLink,
          tone: 'ok',
        },
      ]);
      refreshConvergenceState(true);
    } catch (err) {
      this.renderWorkspaceOutput([
        { label: 'GOOGLE SHEETS ERROR', text: err instanceof Error ? err.message : 'Sheet ingest failed', tone: 'err' },
      ]);
    }
  }

  public async listRecentGmailThreads(): Promise<void> {
    const bridge = getDriveBridgeState();
    const token = getDriveAccessToken();
    if (!bridge.signedIn || !token) {
      this.renderWorkspaceOutput([{ label: 'GMAIL', text: 'Sign in with Google to read recent Gmail headers.', tone: 'warn' }]);
      return;
    }

    try {
      const listData = (await this.driveJsonFetch(
        'https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=4',
        token
      )) as { messages?: Array<{ id: string }> };
      const msgs = listData.messages || [];
      if (msgs.length === 0) {
        this.renderWorkspaceOutput([{ label: 'GMAIL INBOX', text: 'No messages returned.', tone: 'warn' }]);
        return;
      }
      const snippets: Array<{ label: string; text: string; tone: 'ok' }> = [];
      for (const m of msgs.slice(0, 3)) {
        const msgData = (await this.driveJsonFetch(
          `https://gmail.googleapis.com/gmail/v1/users/me/messages/${encodeURIComponent(m.id)}?format=metadata&metadataHeaders=Subject&metadataHeaders=From`,
          token
        )) as { snippet?: string; payload?: { headers?: Array<{ name: string; value: string }> } };
        const subj = msgData.payload?.headers?.find((h) => h.name === 'Subject')?.value || '(No Subject)';
        const from = msgData.payload?.headers?.find((h) => h.name === 'From')?.value || '';
        snippets.push({
          label: `GMAIL: ${subj.slice(0, 42)}`,
          text: `${from} — ${(msgData.snippet || '').slice(0, 90)}`,
          tone: 'ok',
        });
      }
      this.renderWorkspaceOutput(snippets);
    } catch (err) {
      this.renderWorkspaceOutput([
        { label: 'GMAIL ERROR', text: err instanceof Error ? err.message : 'Gmail read failed', tone: 'err' },
      ]);
    }
  }

  public async createAuditGmailDraft(): Promise<void> {
    const bridge = getDriveBridgeState();
    const token = getDriveAccessToken();
    if (!bridge.signedIn || !token) {
      this.renderWorkspaceOutput([{ label: 'GMAIL', text: 'Sign in with Google to compose an audit draft.', tone: 'warn' }]);
      return;
    }

    const summary = sparseBandEngine.getSummary();
    const confirmed = await this.requestExplicitModalConfirmation({
      title: 'Confirm Gmail Audit Draft Creation',
      description: `Create a draft email inside ${bridge.email}'s Gmail containing the current 384 GiB Merkle & Solvent summary?`,
      items: [`To: ${bridge.email}`, `Set1 Root: ${summary.setRootsHex[0].slice(0, 24)}…`],
      confirmLabel: 'CREATE GMAIL DRAFT',
    });
    if (!confirmed) return;

    try {
      const mime = [
        `To: ${bridge.email}`,
        `Subject: GAIA 384 GiB Sparsebundle Verification Receipt`,
        'Content-Type: text/plain; charset="UTF-8"',
        '',
        `Account: ${bridge.email}`,
        `Mounted Volume: ${this.status.mountedLogicalGiB} / 384 GiB (${this.status.mountMode})`,
        `Cyclic Solvent Phase: ${summary.cyclicPhaseMode}`,
        `Set 1 Merkle Root: ${summary.setRootsHex[0]}`,
        `Set 2 Merkle Root: ${summary.setRootsHex[1]}`,
        `Set 3 Merkle Root: ${summary.setRootsHex[2]}`,
      ].join('\r\n');

      await this.driveJsonFetch('https://gmail.googleapis.com/gmail/v1/users/me/drafts', token, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: { raw: utf8ToBase64Url(mime) } }),
      });

      this.renderWorkspaceOutput([
        {
          label: 'GMAIL DRAFT CREATED',
          text: `Saved verification receipt draft in ${bridge.email}'s Drafts folder.`,
          url: 'https://mail.google.com/#drafts',
          tone: 'ok',
        },
      ]);
    } catch (err) {
      this.renderWorkspaceOutput([
        { label: 'GMAIL DRAFT ERROR', text: err instanceof Error ? err.message : 'Unable to create draft', tone: 'err' },
      ]);
    }
  }

  public async listCalendarEvents(): Promise<void> {
    const bridge = getDriveBridgeState();
    const token = getDriveAccessToken();
    if (!bridge.signedIn || !token) {
      this.renderWorkspaceOutput([{ label: 'CALENDAR', text: 'Sign in with Google to view Calendar events.', tone: 'warn' }]);
      return;
    }

    try {
      const params = new URLSearchParams({
        maxResults: '5',
        singleEvents: 'true',
        orderBy: 'startTime',
        timeMin: new Date(Date.now() - 86400_000).toISOString(),
      });
      const data = (await this.driveJsonFetch(
        `https://www.googleapis.com/calendar/v3/calendars/primary/events?${params.toString()}`,
        token
      )) as { items?: Array<{ summary?: string; start?: { dateTime?: string; date?: string } }> };
      const items = data.items || [];
      if (items.length === 0) {
        this.renderWorkspaceOutput([{ label: 'GOOGLE CALENDAR', text: 'No upcoming primary events found.', tone: 'warn' }]);
        return;
      }
      this.renderWorkspaceOutput(
        items.map((ev) => ({
          label: `CALENDAR: ${ev.summary || '(Untitled Event)'}`,
          text: `Start: ${ev.start?.dateTime || ev.start?.date || '--'}`,
          tone: 'ok' as const,
        }))
      );
    } catch (err) {
      this.renderWorkspaceOutput([
        { label: 'CALENDAR ERROR', text: err instanceof Error ? err.message : 'Calendar list failed', tone: 'err' },
      ]);
    }
  }

  public async createMerkleCheckpointCalendarEvent(): Promise<void> {
    const bridge = getDriveBridgeState();
    const token = getDriveAccessToken();
    if (!bridge.signedIn || !token) {
      this.renderWorkspaceOutput([{ label: 'CALENDAR', text: 'Sign in with Google to schedule a Merkle checkpoint.', tone: 'warn' }]);
      return;
    }

    const summary = sparseBandEngine.getSummary();
    const startIso = new Date(Date.now() + 60_000).toISOString();
    const endIso = new Date(Date.now() + 15 * 60_000).toISOString();

    const confirmed = await this.requestExplicitModalConfirmation({
      title: 'Confirm Google Calendar Checkpoint Event',
      description: `Schedule a 15-minute Merkle Checkpoint event on ${bridge.email}'s primary calendar?`,
      items: [
        'Summary: GAIA 384 GiB Merkle & Reverse Verification Checkpoint',
        `Set1 Root: ${summary.setRootsHex[0].slice(0, 24)}…`,
      ],
      confirmLabel: 'SCHEDULE CHECKPOINT',
    });
    if (!confirmed) return;

    try {
      const created = (await this.driveJsonFetch(
        'https://www.googleapis.com/calendar/v3/calendars/primary/events',
        token,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            summary: 'GAIA 384 GiB Merkle & Osmosis Verification Checkpoint',
            description: `Owner: ${bridge.email}\nMounted: ${this.status.mountedLogicalGiB}/384 GiB\nSet1 Root: ${summary.setRootsHex[0]}`,
            start: { dateTime: startIso },
            end: { dateTime: endIso },
          }),
        }
      )) as { htmlLink?: string; summary?: string };

      this.renderWorkspaceOutput([
        {
          label: 'CALENDAR CHECKPOINT CREATED',
          text: created.summary || 'Scheduled GAIA Merkle checkpoint.',
          url: created.htmlLink,
          tone: 'ok',
        },
      ]);
    } catch (err) {
      this.renderWorkspaceOutput([
        { label: 'CALENDAR ERROR', text: err instanceof Error ? err.message : 'Failed to create event', tone: 'err' },
      ]);
    }
  }

  public async createVerificationGoogleTask(): Promise<void> {
    const bridge = getDriveBridgeState();
    const token = getDriveAccessToken();
    if (!bridge.signedIn || !token) {
      this.renderWorkspaceOutput([{ label: 'GOOGLE TASKS', text: 'Sign in with Google to create verification tasks.', tone: 'warn' }]);
      return;
    }

    const summary = sparseBandEngine.getSummary();
    const confirmed = await this.requestExplicitModalConfirmation({
      title: 'Confirm Google Task Creation',
      description: `Add a GAIA Reverse Verification follow-up task in ${bridge.email}'s default Google Tasks list?`,
      items: ['Task: Verify 384 GiB Reverse Sequence (16,383 -> 0)', `Root: ${summary.setRootsHex[0].slice(0, 20)}…`],
      confirmLabel: 'CREATE TASK',
    });
    if (!confirmed) return;

    try {
      const task = (await this.driveJsonFetch(
        'https://tasks.googleapis.com/tasks/v1/lists/@default/tasks',
        token,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            title: `Verify 384 GiB Reverse Sequence (${this.status.mountedLogicalGiB}G)`,
            notes: `Cyclic Phase: ${summary.cyclicPhaseMode} · Set1: ${summary.setRootsHex[0]}`,
          }),
        }
      )) as { title?: string; id?: string };

      this.renderWorkspaceOutput([
        {
          label: 'GOOGLE TASK SAVED',
          text: `Created task "${task.title || 'Verification'}" in @default list.`,
          tone: 'ok',
        },
      ]);
    } catch (err) {
      this.renderWorkspaceOutput([
        { label: 'GOOGLE TASKS ERROR', text: err instanceof Error ? err.message : 'Task creation failed', tone: 'err' },
      ]);
    }
  }

  public async createAuditGoogleSlidesDeck(): Promise<void> {
    const bridge = getDriveBridgeState();
    const token = getDriveAccessToken();
    if (!bridge.signedIn || !token) {
      this.renderWorkspaceOutput([{ label: 'GOOGLE SLIDES', text: 'Sign in with Google to create a Slides audit deck.', tone: 'warn' }]);
      return;
    }

    const title = `GAIA 384 GiB Osmosis Brief (${new Date().toISOString().slice(0, 16)})`;
    const confirmed = await this.requestExplicitModalConfirmation({
      title: 'Confirm Google Slides Presentation Creation',
      description: `Create a new Google Slides deck "${title}" in ${bridge.email}'s Drive?`,
      items: ['slides.googleapis.com/v1/presentations', `Title: ${title}`],
      confirmLabel: 'CREATE SLIDES DECK',
    });
    if (!confirmed) return;

    try {
      const pres = (await this.driveJsonFetch('https://slides.googleapis.com/v1/presentations', token, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title }),
      })) as { presentationId: string; title?: string };

      this.renderWorkspaceOutput([
        {
          label: 'GOOGLE SLIDES CREATED',
          text: `Created presentation "${pres.title || title}".`,
          url: `https://docs.google.com/presentation/d/${encodeURIComponent(pres.presentationId)}/edit`,
          tone: 'ok',
        },
      ]);
    } catch (err) {
      this.renderWorkspaceOutput([
        { label: 'GOOGLE SLIDES ERROR', text: err instanceof Error ? err.message : 'Slides creation failed', tone: 'err' },
      ]);
    }
  }

  public async listAndInspectGoogleForms(): Promise<void> {
    const bridge = getDriveBridgeState();
    const token = getDriveAccessToken();
    if (!bridge.signedIn || !token) {
      this.renderWorkspaceOutput([{ label: 'GOOGLE FORMS', text: 'Sign in with Google to inspect Google Forms.', tone: 'warn' }]);
      return;
    }

    try {
      const params = new URLSearchParams({
        q: "mimeType = 'application/vnd.google-apps.form' and trashed = false",
        pageSize: '5',
        fields: 'files(id,name,webViewLink)',
      });
      const listData = await this.driveJsonFetch(`https://www.googleapis.com/drive/v3/files?${params.toString()}`, token);
      const forms = Array.isArray(listData.files)
        ? (listData.files as Array<{ id: string; name: string; webViewLink?: string }>)
        : [];
      if (forms.length === 0) {
        this.renderWorkspaceOutput([{ label: 'GOOGLE FORMS', text: `No Google Forms found for ${bridge.email}.`, tone: 'warn' }]);
        return;
      }
      const f = forms[0];
      const formDoc = (await this.driveJsonFetch(
        `https://forms.googleapis.com/v1/forms/${encodeURIComponent(f.id)}`,
        token
      )) as { info?: { title?: string }; items?: unknown[] };

      this.renderWorkspaceOutput([
        {
          label: `GOOGLE FORM INSPECTED (${forms.length} Forms)`,
          text: `"${formDoc.info?.title || f.name}" · ${(formDoc.items || []).length} questions/items ready.`,
          url: f.webViewLink,
          tone: 'ok',
        },
      ]);
    } catch (err) {
      this.renderWorkspaceOutput([
        { label: 'GOOGLE FORMS ERROR', text: err instanceof Error ? err.message : 'Forms read failed', tone: 'err' },
      ]);
    }
  }

  public async triggerPostAuthWorkspacePrompt(): Promise<void> {
    const bridge = getDriveBridgeState();
    const res = await promptWorkspaceCapabilitiesUpgrade(bridge.email || undefined);
    this.postAuthBannerDismissed = true;
    this.updateUI();
    this.renderWorkspaceOutput([
      {
        label: 'WORKSPACE AUTHORIZED',
        text: `Full Workspace capabilities active for ${res.email} (Drive, Docs, Meet, Sheets, Gmail, Calendar, Tasks, Slides, Forms).`,
        tone: 'ok',
      },
    ]);
  }

  public init(): void {
    window.addEventListener('gaia-drive-auth-changed', (ev: Event) => {
      const detail = (ev as CustomEvent<{ signedIn: boolean; email: string }>).detail;
      if (detail?.signedIn) {
        void this.discoverAndAttachOnLogin();
      } else {
        void this.unmountOnExit(false);
      }
    });

    window.addEventListener('pagehide', () => {
      void this.unmountOnExit(true);
    });

    document.getElementById('btn-drive-confirm-ok')?.addEventListener('click', () => {
      this.resolveConfirmationModal(true);
    });
    document.getElementById('btn-drive-confirm-cancel')?.addEventListener('click', () => {
      this.resolveConfirmationModal(false);
    });

    for (const btnId of ['btn-drive-mount-sync', 'btn-audit-drive-mount-sync']) {
      document.getElementById(btnId)?.addEventListener('click', () => {
        void this.syncSparseBundleToDrive();
      });
    }
    for (const btnId of ['btn-drive-mount-pull', 'btn-audit-drive-mount-pull']) {
      document.getElementById(btnId)?.addEventListener('click', () => {
        void this.discoverAndAttachOnLogin();
      });
    }
    for (const btnId of ['btn-drive-unmount', 'btn-audit-drive-unmount']) {
      document.getElementById(btnId)?.addEventListener('click', () => {
        void this.unmountOnExit(false);
      });
    }
    document.getElementById('btn-drive-export-rclone')?.addEventListener('click', () => {
      this.downloadRcloneHelperBundle();
    });
    document.getElementById('btn-rclone-download-conf')?.addEventListener('click', () => {
      void this.downloadSanitizedRcloneConf();
    });
    document.getElementById('btn-rclone-apply-conf')?.addEventListener('click', () => {
      const editor = document.getElementById('rclone-conf-editor') as HTMLTextAreaElement | null;
      const out = this.parseAndApplyRcloneConf(editor?.value || '');
      this.renderWorkspaceOutput([{ label: 'RCLONE.CONF', text: out.message, tone: 'ok' }]);
    });
    document.getElementById('rclone-conf-file-input')?.addEventListener('change', async (ev: Event) => {
      const input = ev.target as HTMLInputElement;
      const file = input.files?.[0];
      if (!file) return;
      const txt = await file.text();
      const editor = document.getElementById('rclone-conf-editor') as HTMLTextAreaElement | null;
      if (editor) editor.value = txt;
      const out = this.parseAndApplyRcloneConf(txt);
      this.renderWorkspaceOutput([{ label: `RCLONE FILE (${file.name})`, text: out.message, tone: 'ok' }]);
    });

    document.getElementById('btn-clip-mount-all')?.addEventListener('click', () => {
      void this.mountAllFusionTiers();
    });
    document.getElementById('btn-workspace-postauth-upgrade')?.addEventListener('click', () => {
      void this.triggerPostAuthWorkspacePrompt();
    });
    document.getElementById('btn-workspace-postauth-dismiss')?.addEventListener('click', () => {
      this.postAuthBannerDismissed = true;
      this.updateUI();
    });

    document.getElementById('btn-docs-list-ingest')?.addEventListener('click', () => {
      void this.readAndIngestGoogleDocs();
    });
    document.getElementById('btn-docs-create-audit')?.addEventListener('click', () => {
      void this.createAuditReceiptGoogleDoc();
    });
    document.getElementById('btn-meet-create-space')?.addEventListener('click', () => {
      void this.createVerifiedMeetSpace();
    });
    document.getElementById('btn-meet-list-records')?.addEventListener('click', () => {
      void this.listMeetConferenceRecords();
    });
    document.getElementById('btn-sheets-export')?.addEventListener('click', () => {
      void this.exportSparseBandsToGoogleSheet();
    });
    document.getElementById('btn-sheets-ingest')?.addEventListener('click', () => {
      void this.readAndIngestGoogleSheet();
    });
    document.getElementById('btn-gmail-list')?.addEventListener('click', () => {
      void this.listRecentGmailThreads();
    });
    document.getElementById('btn-gmail-draft')?.addEventListener('click', () => {
      void this.createAuditGmailDraft();
    });
    document.getElementById('btn-calendar-list')?.addEventListener('click', () => {
      void this.listCalendarEvents();
    });
    document.getElementById('btn-calendar-create')?.addEventListener('click', () => {
      void this.createMerkleCheckpointCalendarEvent();
    });
    document.getElementById('btn-tasks-create')?.addEventListener('click', () => {
      void this.createVerificationGoogleTask();
    });
    document.getElementById('btn-slides-create')?.addEventListener('click', () => {
      void this.createAuditGoogleSlidesDeck();
    });
    document.getElementById('btn-forms-inspect')?.addEventListener('click', () => {
      void this.listAndInspectGoogleForms();
    });

    const st = getDriveBridgeState();
    if (st.signedIn) {
      void this.discoverAndAttachOnLogin();
    } else {
      this.updateUI();
      void this.refreshRcloneConfPreview(true);
    }
  }
}

export const driveSparseMount = new DriveSparseMountController();

export function initDriveSparseMount(): void {
  driveSparseMount.init();
  (window as unknown as Record<string, unknown>).__gaiaDriveSparseMount = {
    getStatus: () => driveSparseMount.getStatus(),
    syncToDrive: () => driveSparseMount.syncSparseBundleToDrive(),
    attachFromDrive: () => driveSparseMount.discoverAndAttachOnLogin(),
    unmount: () => driveSparseMount.unmountOnExit(false),
    toggleFusionTier: (tierId: SparseFusionTierId) => driveSparseMount.toggleFusionTier(tierId),
    mountAllFusionTiers: () => driveSparseMount.mountAllFusionTiers(),
    downloadRcloneScript: () => driveSparseMount.downloadRcloneHelperBundle(),
    downloadSanitizedRcloneConf: () => driveSparseMount.downloadSanitizedRcloneConf(),
    parseAndApplyRcloneConf: (txt: string) => driveSparseMount.parseAndApplyRcloneConf(txt),
    readAndIngestGoogleDocs: () => driveSparseMount.readAndIngestGoogleDocs(),
    createAuditReceiptGoogleDoc: () => driveSparseMount.createAuditReceiptGoogleDoc(),
    createVerifiedMeetSpace: () => driveSparseMount.createVerifiedMeetSpace(),
    listMeetConferenceRecords: () => driveSparseMount.listMeetConferenceRecords(),
    exportSparseBandsToGoogleSheet: () => driveSparseMount.exportSparseBandsToGoogleSheet(),
    readAndIngestGoogleSheet: () => driveSparseMount.readAndIngestGoogleSheet(),
    listRecentGmailThreads: () => driveSparseMount.listRecentGmailThreads(),
    createAuditGmailDraft: () => driveSparseMount.createAuditGmailDraft(),
    listCalendarEvents: () => driveSparseMount.listCalendarEvents(),
    createMerkleCheckpointCalendarEvent: () => driveSparseMount.createMerkleCheckpointCalendarEvent(),
    createVerificationGoogleTask: () => driveSparseMount.createVerificationGoogleTask(),
    createAuditGoogleSlidesDeck: () => driveSparseMount.createAuditGoogleSlidesDeck(),
    listAndInspectGoogleForms: () => driveSparseMount.listAndInspectGoogleForms(),
  };
}
