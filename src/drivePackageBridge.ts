import { initializeApp } from 'firebase/app';
import {
  getAuth,
  signInWithPopup,
  GoogleAuthProvider,
  onAuthStateChanged,
  User,
} from 'firebase/auth';
import firebaseConfig from '../firebase-applet-config.json';

export const DRIVE_SCOPES = [
  'https://www.googleapis.com/auth/drive.readonly',
  'https://www.googleapis.com/auth/drive.file',
  'https://www.googleapis.com/auth/drive',
  'https://www.googleapis.com/auth/documents',
  'https://www.googleapis.com/auth/documents.readonly',
  'https://www.googleapis.com/auth/meetings.space.created',
  'https://www.googleapis.com/auth/meetings.space.readonly',
  'https://www.googleapis.com/auth/meetings.space.settings',
  'https://www.googleapis.com/auth/spreadsheets',
  'https://www.googleapis.com/auth/spreadsheets.readonly',
  'https://www.googleapis.com/auth/gmail.readonly',
  'https://www.googleapis.com/auth/gmail.compose',
  'https://www.googleapis.com/auth/calendar.events',
  'https://www.googleapis.com/auth/calendar.readonly',
  'https://www.googleapis.com/auth/tasks',
  'https://www.googleapis.com/auth/presentations',
  'https://www.googleapis.com/auth/forms.body.readonly',
  'https://www.googleapis.com/auth/userinfo.profile',
  'https://www.googleapis.com/auth/userinfo.email',
] as const;

export interface DriveQuotaSnapshot {
  limitBytes: number | null;
  usageBytes: number;
  freeBytes: number | null;
  unlimitedDriveStorage: boolean;
  fitsFull384GiB: boolean;
  fitsLegacy192GiB: boolean;
  quotaKnown: boolean;
  email: string;
  displayName: string;
  checkedAt: string;
}

export function isMachackabookAccount(email: string, displayName = ''): boolean {
  const hay = `${email} ${displayName}`.toLowerCase();
  return hay.includes('machackabook');
}

export type ProviderKey = 'GEMINI' | 'IBM_GRANITE' | 'GPT' | 'KERNEL_LOCAL';

export interface ProviderSpec {
  key: ProviderKey;
  designation: string;
  packageName: string;
  models: string[];
  runtime: string;
  exactMarkers: string[];
}

export interface DrivePackageMatch {
  fileId: string;
  fileName: string;
  mimeType: string;
  modifiedTime: string;
  sizeBytes: number;
  sha256Checksum: string;
  providerKey: ProviderKey;
  matchedModel: string;
  matchedPackage: string;
  exactCaseMatch: boolean;
  matchReason: string;
  manifestSnippet: string;
}

export interface DriveScanResult {
  ok: boolean;
  filesScanned: number;
  matches: DrivePackageMatch[];
  error?: string;
}

export const PROVIDER_SPECS: Record<ProviderKey, ProviderSpec> = {
  GEMINI: {
    key: 'GEMINI',
    designation: 'AE.AI.GEMINI',
    packageName: '@google/genai',
    models: ['gemini-2.5-flash', 'gemini-2.5-pro', 'gemini-3-flash-preview', 'gemini-3.1-pro-preview'],
    runtime: 'GOOGLE_AI_SDK',
    exactMarkers: ['@google/genai', 'gemini-2.5-flash', 'gemini-2.5-pro', 'gemini-3-flash-preview', 'GEMINI'],
  },
  IBM_GRANITE: {
    key: 'IBM_GRANITE',
    designation: 'AE.AI.IBM.GRANITE',
    packageName: 'AE.AI.IBM.GRANITE',
    models: ['ibm/granite-4-h-small', 'ibm/granite-guardian', 'ibm/granite-embedding', 'ibm/granite-code'],
    runtime: 'WATSONX_AI',
    exactMarkers: ['AE.AI.IBM.GRANITE', 'IBM_GRANITE', 'GRANITE_REGISTRY', 'ibm/granite-4-h-small', 'WATSONX_AI'],
  },
  GPT: {
    key: 'GPT',
    designation: 'AE.AI.FEDERATION.GPT',
    packageName: 'AE.AI.FEDERATION',
    models: ['gpt-5', 'gpt-5-mini', 'gpt-4.1'],
    runtime: 'AE.AI.FEDERATION',
    exactMarkers: ['AE.AI.FEDERATION', 'gpt-5', 'gpt-5-mini', 'GPT'],
  },
  KERNEL_LOCAL: {
    key: 'KERNEL_LOCAL',
    designation: 'AE.SL6.DUALTRACE.4P',
    packageName: 'AE.SL6.DUALTRACE.4P',
    models: ['U(97152)', 'T=I_R∘D', 'kernel-lifetimes'],
    runtime: 'DETERMINISTIC_WEBGL_WASM',
    exactMarkers: ['AE.SL6.DUALTRACE.4P', 'U(97152)', 'kernel-lifetimes', 'KERNEL_LOCAL'],
  },
};

const app = initializeApp(firebaseConfig as Record<string, string>);
const auth = getAuth(app);

export interface UserSessionProfile {
  uid: string;
  email: string;
  displayName: string;
  photoURL?: string;
  accessToken: string;
  signedInAt: string;
  machackabookMatched?: boolean;
  quota?: DriveQuotaSnapshot | null;
}

const LOGICAL_384_GIB_BYTES = 49_152 * 8_388_608; // 412,316,860,416 B
const LOGICAL_192_GIB_BYTES = 24_576 * 8_388_608; // 206,158,430,208 B

// In-memory multi-user sessions cache ONLY — never persisted to localStorage or sessionStorage
const userSessions = new Map<string, UserSessionProfile>();
let activeUid: string | null = null;
let cachedAccessToken: string | null = null;
let currentUser: User | null = null;
let isSigningIn = false;

function emitAuthState(): void {
  window.dispatchEvent(
    new CustomEvent('gaia-drive-auth-changed', {
      detail: getDriveBridgeState(),
    })
  );
}

export function getDriveAccessToken(): string | null {
  return cachedAccessToken;
}

export function getAllUserSessions(): UserSessionProfile[] {
  return Array.from(userSessions.values());
}

export function switchActiveUser(uid: string): boolean {
  const session = userSessions.get(uid);
  if (!session) return false;
  activeUid = uid;
  cachedAccessToken = session.accessToken;
  currentUser = (session as unknown as { user?: User }).user || currentUser;
  emitAuthState();
  return true;
}

export function removeUserSession(uid: string): void {
  userSessions.delete(uid);
  if (activeUid === uid) {
    const next = userSessions.values().next().value;
    if (next) {
      activeUid = next.uid;
      cachedAccessToken = next.accessToken;
      currentUser = (next as unknown as { user?: User }).user || null;
    } else {
      activeUid = null;
      cachedAccessToken = null;
      currentUser = null;
    }
  }
  emitAuthState();
}

export function getDriveBridgeState() {
  const sessions = getAllUserSessions();
  const activeSession = activeUid ? userSessions.get(activeUid) || null : null;
  const email = activeSession?.email || currentUser?.email || '';
  const displayName = activeSession?.displayName || currentUser?.displayName || '';
  return {
    signedIn: Boolean(currentUser && cachedAccessToken),
    hasFirebaseUser: Boolean(currentUser),
    hasToken: Boolean(cachedAccessToken),
    activeUid: activeUid || currentUser?.uid || '',
    email,
    displayName,
    photoURL: activeSession?.photoURL || currentUser?.photoURL || '',
    machackabookDetected: isMachackabookAccount(email, displayName),
    quota: activeSession?.quota || null,
    sessions,
    totalUsers: sessions.length,
    scopes: [...DRIVE_SCOPES],
  };
}

export async function fetchDriveQuotaAndProfile(tokenOverride?: string): Promise<DriveQuotaSnapshot | null> {
  const token = tokenOverride || cachedAccessToken;
  if (!token) return null;
  try {
    const res = await fetch(
      'https://www.googleapis.com/drive/v3/about?fields=storageQuota,user(emailAddress,displayName)',
      { headers: { Authorization: `Bearer ${token}` } }
    );
    if (!res.ok) return null;
    const data = (await res.json()) as {
      storageQuota?: { limit?: string; usage?: string; usageInDrive?: string };
      user?: { emailAddress?: string; displayName?: string };
    };
    const sq = data.storageQuota || {};
    const limitParsed = sq.limit !== undefined ? Number(sq.limit) : NaN;
    const usageParsed = Number(sq.usage ?? sq.usageInDrive ?? 0);
    const unlimitedDriveStorage = sq.limit === undefined || !Number.isFinite(limitParsed) || limitParsed <= 0;
    const limitBytes = unlimitedDriveStorage ? null : limitParsed;
    const usageBytes = Number.isFinite(usageParsed) ? usageParsed : 0;
    const freeBytes = limitBytes !== null ? Math.max(0, limitBytes - usageBytes) : null;
    const email = String(data.user?.emailAddress || currentUser?.email || '');
    const displayName = String(data.user?.displayName || currentUser?.displayName || email);

    const snapshot: DriveQuotaSnapshot = {
      limitBytes,
      usageBytes,
      freeBytes,
      unlimitedDriveStorage,
      fitsFull384GiB: unlimitedDriveStorage || (freeBytes !== null && freeBytes >= LOGICAL_384_GIB_BYTES),
      fitsLegacy192GiB: unlimitedDriveStorage || (freeBytes !== null && freeBytes >= LOGICAL_192_GIB_BYTES),
      quotaKnown: true,
      email,
      displayName,
      checkedAt: new Date().toISOString(),
    };

    if (activeUid && userSessions.has(activeUid)) {
      const sess = userSessions.get(activeUid)!;
      sess.quota = snapshot;
      sess.machackabookMatched = isMachackabookAccount(email, displayName);
    }
    emitAuthState();
    return snapshot;
  } catch {
    return null;
  }
}

export function initGaiaDriveBridge(): () => void {
  const unsub = onAuthStateChanged(auth, (user) => {
    if (!user) {
      if (userSessions.size === 0) {
        cachedAccessToken = null;
        currentUser = null;
        activeUid = null;
      }
    } else {
      currentUser = user;
    }
    emitAuthState();
  });

  (window as unknown as Record<string, unknown>).__gaiaDriveBridge = {
    SCOPES: [...DRIVE_SCOPES],
    PROVIDER_SPECS,
    getState: getDriveBridgeState,
    getAllSessions: getAllUserSessions,
    switchUser: switchActiveUser,
    removeUser: removeUserSession,
    signIn: googleDriveSignIn,
    signOut: googleDriveSignOut,
    signOutAll: googleDriveSignOutAll,
    promptWorkspaceCapabilitiesUpgrade,
    fetchDriveQuotaAndProfile,
    isMachackabookAccount,
    scanExactProviderPackages,
  };

  emitAuthState();
  return unsub;
}

export async function googleDriveSignIn(loginHint?: string) {
  isSigningIn = true;
  try {
    const activeProvider = new GoogleAuthProvider();
    DRIVE_SCOPES.forEach((scope) => activeProvider.addScope(scope));
    const params: Record<string, string> = {
      prompt: 'select_account',
      include_granted_scopes: 'true',
    };
    if (loginHint && loginHint.trim()) {
      params.login_hint = loginHint.trim();
    }
    activeProvider.setCustomParameters(params);

    const result = await signInWithPopup(auth, activeProvider);
    const credential = GoogleAuthProvider.credentialFromResult(result);
    if (!credential?.accessToken) {
      throw new Error('Google Workspace access token was not returned. Retry Sign in with Google.');
    }
    const email = result.user.email || 'unknown@google.com';
    const displayName = result.user.displayName || email;
    const session: UserSessionProfile = {
      uid: result.user.uid,
      email,
      displayName,
      photoURL: result.user.photoURL || undefined,
      accessToken: credential.accessToken,
      signedInAt: new Date().toISOString(),
      machackabookMatched: isMachackabookAccount(email, displayName),
      quota: null,
    };
    (session as unknown as Record<string, unknown>).user = result.user;
    userSessions.set(session.uid, session);
    activeUid = session.uid;
    currentUser = result.user;
    cachedAccessToken = credential.accessToken;
    emitAuthState();
    await fetchDriveQuotaAndProfile(credential.accessToken);
    return getDriveBridgeState();
  } finally {
    isSigningIn = false;
  }
}

export async function promptWorkspaceCapabilitiesUpgrade(loginHint?: string) {
  isSigningIn = true;
  try {
    const upgradeProvider = new GoogleAuthProvider();
    DRIVE_SCOPES.forEach((scope) => upgradeProvider.addScope(scope));
    const activeHint = loginHint || currentUser?.email || '';
    const params: Record<string, string> = {
      prompt: 'consent select_account',
      include_granted_scopes: 'true',
    };
    if (activeHint) params.login_hint = activeHint;
    upgradeProvider.setCustomParameters(params);

    const result = await signInWithPopup(auth, upgradeProvider);
    const credential = GoogleAuthProvider.credentialFromResult(result);
    if (!credential?.accessToken) {
      throw new Error('Google Workspace upgrade token was not returned.');
    }
    const email = result.user.email || activeHint || 'unknown@google.com';
    const displayName = result.user.displayName || email;
    const session: UserSessionProfile = {
      uid: result.user.uid,
      email,
      displayName,
      photoURL: result.user.photoURL || undefined,
      accessToken: credential.accessToken,
      signedInAt: new Date().toISOString(),
      machackabookMatched: isMachackabookAccount(email, displayName),
      quota: null,
    };
    (session as unknown as Record<string, unknown>).user = result.user;
    userSessions.set(session.uid, session);
    activeUid = session.uid;
    currentUser = result.user;
    cachedAccessToken = credential.accessToken;
    emitAuthState();
    await fetchDriveQuotaAndProfile(credential.accessToken);
    return getDriveBridgeState();
  } finally {
    isSigningIn = false;
  }
}

export async function googleDriveSignOut() {
  if (activeUid) {
    removeUserSession(activeUid);
  } else {
    await googleDriveSignOutAll();
  }
}

export async function googleDriveSignOutAll() {
  await auth.signOut();
  userSessions.clear();
  activeUid = null;
  cachedAccessToken = null;
  currentUser = null;
  emitAuthState();
}

function matchFileAgainstSpecs(
  fileName: string,
  description: string,
  bodyText: string,
  filterProvider: ProviderKey | 'ALL'
): { spec: ProviderSpec; model: string; exactCaseMatch: boolean; reason: string } | null {
  const specsToCheck =
    filterProvider === 'ALL'
      ? Object.values(PROVIDER_SPECS)
      : [PROVIDER_SPECS[filterProvider]].filter(Boolean);

  const combined = `${fileName}\n${description}\n${bodyText}`;

  for (const spec of specsToCheck) {
    // 1. Exact case-sensitive match against declared packageName / models / markers
    if (combined.includes(spec.packageName)) {
      return {
        spec,
        model: spec.models[0],
        exactCaseMatch: true,
        reason: `Exact package match: ${spec.packageName}`,
      };
    }
    for (const model of spec.models) {
      if (combined.includes(model)) {
        return {
          spec,
          model,
          exactCaseMatch: true,
          reason: `Exact model identifier match: ${model}`,
        };
      }
    }
    for (const marker of spec.exactMarkers) {
      if (combined.includes(marker)) {
        return {
          spec,
          model: spec.models[0],
          exactCaseMatch: true,
          reason: `Exact marker match: ${marker}`,
        };
      }
    }
  }
  return null;
}

export async function scanExactProviderPackages(
  filterProvider: ProviderKey | 'ALL' = 'ALL'
): Promise<DriveScanResult> {
  if (!cachedAccessToken) {
    return {
      ok: false,
      filesScanned: 0,
      matches: [],
      error: 'Sign in with Google required to query Google Drive.',
    };
  }

  try {
    const params = new URLSearchParams({
      q: 'trashed = false',
      pageSize: '100',
      fields: 'files(id,name,mimeType,modifiedTime,size,sha256Checksum,description)',
    });
    const listRes = await fetch(
      `https://www.googleapis.com/drive/v3/files?${params.toString()}`,
      {
        headers: {
          Authorization: `Bearer ${cachedAccessToken}`,
        },
      }
    );

    if (listRes.status === 401 || listRes.status === 403) {
      cachedAccessToken = null;
      emitAuthState();
      return {
        ok: false,
        filesScanned: 0,
        matches: [],
        error: 'Drive session expired or permission denied. Please Sign in with Google again.',
      };
    }

    if (!listRes.ok) {
      throw new Error(`Drive API HTTP ${listRes.status}`);
    }

    const json = await listRes.json();
    const files: Array<Record<string, string>> = Array.isArray(json.files) ? json.files : [];
    const matches: DrivePackageMatch[] = [];

    // Inspect metadata + selectively fetch small manifest text/json/xml files for exact package verification
    let contentReads = 0;
    for (const f of files) {
      const name = String(f.name || '');
      const mime = String(f.mimeType || '');
      const desc = String(f.description || '');
      const sizeBytes = Number(f.size || 0);

      let bodyText = '';
      const isReadableManifest =
        (mime.includes('json') ||
          mime.includes('text') ||
          mime.includes('xml') ||
          /\.(json|txt|xml|yaml|yml|md)$/i.test(name)) &&
        sizeBytes > 0 &&
        sizeBytes <= 262144;

      if (isReadableManifest && contentReads < 12) {
        contentReads++;
        try {
          const mediaRes = await fetch(
            `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(f.id)}?alt=media`,
            {
              headers: {
                Authorization: `Bearer ${cachedAccessToken}`,
              },
            }
          );
          if (mediaRes.ok) {
            bodyText = (await mediaRes.text()).slice(0, 16384);
          }
        } catch {
          // Ignore unreadable individual blob
        }
      }

      const hit = matchFileAgainstSpecs(name, desc, bodyText, filterProvider);
      if (hit) {
        matches.push({
          fileId: f.id,
          fileName: name,
          mimeType: mime,
          modifiedTime: f.modifiedTime || '',
          sizeBytes,
          sha256Checksum: f.sha256Checksum || '',
          providerKey: hit.spec.key,
          matchedModel: hit.model,
          matchedPackage: hit.spec.packageName,
          exactCaseMatch: hit.exactCaseMatch,
          matchReason: hit.reason,
          manifestSnippet: bodyText ? bodyText.slice(0, 140).replace(/\s+/g, ' ') : desc || name,
        });
      }
    }

    return {
      ok: true,
      filesScanned: files.length,
      matches,
    };
  } catch (err) {
    return {
      ok: false,
      filesScanned: 0,
      matches: [],
      error: err instanceof Error ? err.message : 'Google Drive scan failed',
    };
  }
}
