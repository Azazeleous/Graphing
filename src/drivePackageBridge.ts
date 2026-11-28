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
] as const;

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

const provider = new GoogleAuthProvider();
DRIVE_SCOPES.forEach((scope) => provider.addScope(scope));
provider.setCustomParameters({ prompt: 'select_account' });

export interface UserSessionProfile {
  uid: string;
  email: string;
  displayName: string;
  photoURL?: string;
  accessToken: string;
  signedInAt: string;
}

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
  currentUser = session.user as unknown as User;
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
      currentUser = next.user as unknown as User;
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
  return {
    signedIn: Boolean(currentUser && cachedAccessToken),
    hasFirebaseUser: Boolean(currentUser),
    hasToken: Boolean(cachedAccessToken),
    activeUid: activeUid || currentUser?.uid || '',
    email: currentUser?.email || '',
    displayName: currentUser?.displayName || '',
    photoURL: currentUser?.photoURL || '',
    sessions,
    totalUsers: sessions.length,
    scopes: [...DRIVE_SCOPES],
  };
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
    scanExactProviderPackages,
  };

  emitAuthState();
  return unsub;
}

export async function googleDriveSignIn() {
  isSigningIn = true;
  try {
    const result = await signInWithPopup(auth, provider);
    const credential = GoogleAuthProvider.credentialFromResult(result);
    if (!credential?.accessToken) {
      throw new Error('Google Workspace access token was not returned. Retry Sign in with Google.');
    }
    const session: UserSessionProfile = {
      uid: result.user.uid,
      email: result.user.email || 'unknown@google.com',
      displayName: result.user.displayName || result.user.email || 'Google User',
      photoURL: result.user.photoURL || undefined,
      accessToken: credential.accessToken,
      signedInAt: new Date().toISOString(),
    };
    (session as unknown as Record<string, unknown>).user = result.user;
    userSessions.set(session.uid, session);
    activeUid = session.uid;
    currentUser = result.user;
    cachedAccessToken = credential.accessToken;
    emitAuthState();
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
