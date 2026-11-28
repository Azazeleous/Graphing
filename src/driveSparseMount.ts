import {
  getDriveAccessToken,
  getDriveBridgeState,
} from './drivePackageBridge.ts';
import {
  sparseBandEngine,
  SPARSE_BAND_TOTAL_BYTES,
  TOTAL_HYPER_BLOCKS,
  LOGICAL_VOLUME_BYTES,
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
  driveFolderId: string | null;
  bandsFolderId: string | null;
  manifestFileId: string | null;
  plistFileId: string | null;
  logicalVolumeBytes: number;
  logicalVolumeGiB: number;
  bandSizeBytes: number;
  totalSparseBands: number;
  uploadedDriveBands: number;
  httpfsMounted: boolean;
  lastSyncAt: string | null;
  message: string;
}

const SPARSEBUNDLE_FOLDER_NAME = 'GAIA_NEXUS_192GiB.sparsebundle';
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

class DriveSparseMountController {
  private status: DriveSparseMountStatus = {
    lifecycle: 'UNMOUNTED',
    signedIn: false,
    ownerEmail: '',
    driveFolderId: null,
    bandsFolderId: null,
    manifestFileId: null,
    plistFileId: null,
    logicalVolumeBytes: LOGICAL_VOLUME_BYTES,
    logicalVolumeGiB: 192,
    bandSizeBytes: SPARSE_BAND_TOTAL_BYTES,
    totalSparseBands: TOTAL_HYPER_BLOCKS,
    uploadedDriveBands: 0,
    httpfsMounted: false,
    lastSyncAt: null,
    message: 'Sign in with Google to attach your 192 GiB .sparsebundle & HTTPFS virtual disk.',
  };

  private pendingConfirmResolver: ((confirmed: boolean) => void) | null = null;
  private isHandlingAuth = false;

  public getStatus(): DriveSparseMountStatus {
    return { ...this.status };
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
      ? `MOUNTED (DRIVE+HTTPFS) · 192 GiB · ${s.uploadedDriveBands} bands synced (${s.ownerEmail})`
      : s.message;

    for (const id of ['drive-sparse-mount-badge', 'audit-drive-mount-badge']) {
      const el = document.getElementById(id);
      if (el) {
        el.className = `text-[8.5px] font-semibold tabular-nums truncate ${pillCls}`;
        el.textContent = isMounted ? 'MOUNTED · 192 GiB HTTPFS' : s.lifecycle;
      }
    }

    for (const id of ['drive-sparse-mount-detail', 'audit-drive-mount-detail']) {
      const el = document.getElementById(id);
      if (el) el.textContent = summaryText;
    }

    const rcloneBox = document.getElementById('drive-rclone-cmd-ui');
    if (rcloneBox) {
      const origin = window.location.origin;
      rcloneBox.textContent = `rclone mount :http:/v1/sparsebundle/httpfs/GAIA_NEXUS_192GiB.sparsebundle /mnt/gaia192 --http-url ${origin} --vfs-cache-mode full`;
    }
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
      throw new Error(`Drive API HTTP ${res.status}: ${txt.slice(0, 140)}`);
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
        format: 'GAIA_SPARSEBAND_8MIB_V1',
        setIndex: d.setIndex,
        blockIndex: d.blockIndex,
        cells: sparseBandEngine.cells.filter((c) => c.setIndex === d.setIndex && c.blockIndex === d.blockIndex),
      }).slice(0, 250_000),
    }));

    const body = {
      driveFolderId: this.status.driveFolderId,
      bandsFolderId: this.status.bandsFolderId,
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
  }

  /**
   * Read-only discovery triggered automatically when the user signs in with Google.
   * Hydrates existing Google Drive .sparsebundle manifest + attaches HTTPFS volume cleanly.
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
    this.status.signedIn = true;
    this.status.ownerEmail = bridge.email;
    this.status.lifecycle = 'DISCOVERING_DRIVE';
    this.status.message = `Signed in as ${bridge.email} — scanning Google Drive for 192 GiB sparsebundle…`;
    this.updateUI();

    try {
      const rootFolder = await this.findDriveFile(token, SPARSEBUNDLE_FOLDER_NAME, null, MIME_FOLDER);
      if (!rootFolder) {
        await this.mountBandsToHttpfsGateway(token);
        this.status.lifecycle = 'NEEDS_DRIVE_INIT';
        this.status.driveFolderId = null;
        this.status.bandsFolderId = null;
        this.status.message = `HTTPFS attached (192 GiB). Click SYNC 192GiB TO DRIVE to save bands to ${bridge.email}'s Drive.`;
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
      this.status.message = `Attached ${SPARSEBUNDLE_FOLDER_NAME} from ${bridge.email} (${remoteBandCount} Drive bands, +${hydratedCount} hydrated cells).`;

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

  /**
   * Creates or updates the 192 GiB .sparsebundle on the signed-in user's Google Drive
   * ONLY after explicit confirmation via the in-app confirmation modal.
   */
  public async syncSparseBundleToDrive(): Promise<boolean> {
    const bridge = getDriveBridgeState();
    const token = getDriveAccessToken();
    if (!bridge.signedIn || !token) {
      this.status.lifecycle = 'ERROR';
      this.status.message = 'Sign in with Google first to sync your sparsebundle to Google Drive.';
      this.updateUI();
      return false;
    }

    const descriptors = sparseBandEngine.getPopulatedBandDescriptors().slice(0, 4);
    const affectedItems = [
      `${SPARSEBUNDLE_FOLDER_NAME}/ (Google Drive root folder)`,
      `Info.plist (192 GiB = ${LOGICAL_VOLUME_BYTES.toLocaleString()} B sparsebundle descriptor)`,
      'mount.token.json (signed-in session attach lease)',
      `GAIA_MANIFEST.json (${sparseBandEngine.cells.length} verified BLAKE2b+SHA256d cells)`,
      ...descriptors.map(
        (d) => `bands/${d.bandHex} (real 8,388,608-byte 8 MiB sparse band · Set ${d.setIndex + 1} Blk #${d.blockIndex})`
      ),
    ];

    const confirmed = await this.requestExplicitModalConfirmation({
      title: 'Confirm Google Drive 192 GiB Sparsebundle Sync',
      description: `Upload and update ${affectedItems.length} items inside Google Drive for ${bridge.email}? Existing files in ${SPARSEBUNDLE_FOLDER_NAME} will be updated.`,
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
          logicalVolumeGiB: 192,
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
        schema: 'GAIA_192GIB_SPARSEBUNDLE_V1',
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
          capacity: { state: 'PASS', reason: `${uploadedCount} real 8 MiB bands + 192 GiB Info.plist synced` },
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
    this.status.lifecycle = 'UNMOUNTED';
    this.status.message = bridge.signedIn
      ? `HTTPFS unmounted cleanly for ${bridge.email}.`
      : 'Signed out — virtual 192 GiB HTTPFS mount released.';
    this.updateUI();
  }

  public downloadRcloneHelperBundle(): void {
    const origin = window.location.origin;
    const scriptText = [
      '#!/usr/bin/env bash',
      '# GAIA NEXUS 192 GiB Sparsebundle HTTPFS & Google Drive rclone Mount Helper',
      `# Volume Size: 192 GiB (${LOGICAL_VOLUME_BYTES} bytes = ${TOTAL_HYPER_BLOCKS} x 8 MiB sparse bands)`,
      'set -euo pipefail',
      '',
      'MOUNT_POINT="${1:-$HOME/mnt/gaia_192gib}"',
      'mkdir -p "$MOUNT_POINT"',
      '',
      '# Option A: Mount live HTTPFS virtual 192 GiB disk served by this app:',
      `rclone mount :http:/v1/sparsebundle/httpfs/GAIA_NEXUS_192GiB.sparsebundle "$MOUNT_POINT" \\`,
      `  --http-url "${origin}" \\`,
      '  --vfs-cache-mode full \\',
      '  --read-only',
      '',
      '# Option B: Mount directly from your Google Drive remote (after configuring "rclone config" drive remote "gdrive"):',
      `# rclone mount gdrive:${SPARSEBUNDLE_FOLDER_NAME} "$MOUNT_POINT" --vfs-cache-mode writes`,
      '',
    ].join('\n');

    const blob = new Blob([scriptText], { type: 'text/x-shellscript' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'mount_192gib_sparsebundle.sh';
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
      if (item.url && /^https:\/\/meet\.google\.com\/|^https:\/\/docs\.google\.com\//.test(item.url)) {
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
          text: `"${docJson.title || firstDoc.name}" -> ${ingested.insertedCells.length} BLAKE2b+SHA256d cells packed into 8 MiB sparseband (Dewey ${ingested.insertedCells[0]?.deweyAddress ?? '--'}).`,
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
    const docTitle = `GAIA 192GiB Sparsebundle Audit (${new Date().toISOString().slice(0, 16)})`;
    const confirmed = await this.requestExplicitModalConfirmation({
      title: 'Confirm Google Doc Creation',
      description: `Create a new Google Doc in ${bridge.email}'s account summarizing live 192 GiB sparsebundle Merkle roots and Dewey cells?`,
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
        `GAIA NEXUS 192 GiB Sparsebundle & BLAKE2b Merkle Receipt`,
        `Signed-in Owner: ${bridge.email}`,
        `Logical Capacity: 192 GiB (${LOGICAL_VOLUME_BYTES.toLocaleString()} bytes across ${TOTAL_HYPER_BLOCKS.toLocaleString()} x 8 MiB bands)`,
        `Set 1 Merkle Root: ${summary.setRootsHex[0]}`,
        `Set 2 Merkle Root: ${summary.setRootsHex[1]}`,
        `Set 3 Merkle Root: ${summary.setRootsHex[2]}`,
        `Indexed Cells: ${summary.populatedCellsCount} | Populated Bands: ${summary.populatedBandsCount}`,
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
      description: `Create a new Google Meet conference space under ${bridge.email} with Open access settings?`,
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

    const st = getDriveBridgeState();
    if (st.signedIn) {
      void this.discoverAndAttachOnLogin();
    } else {
      this.updateUI();
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
    downloadRcloneScript: () => driveSparseMount.downloadRcloneHelperBundle(),
    readAndIngestGoogleDocs: () => driveSparseMount.readAndIngestGoogleDocs(),
    createAuditReceiptGoogleDoc: () => driveSparseMount.createAuditReceiptGoogleDoc(),
    createVerifiedMeetSpace: () => driveSparseMount.createVerifiedMeetSpace(),
    listMeetConferenceRecords: () => driveSparseMount.listMeetConferenceRecords(),
  };
}
