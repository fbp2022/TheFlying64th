// auth.js (Firebase v12.5.0) — simplified for admin/member + /profiles only

import { initializeApp, getApps, getApp } from "https://www.gstatic.com/firebasejs/12.5.0/firebase-app.js";
import {
  getAuth,
  onAuthStateChanged,
  setPersistence,
  browserLocalPersistence,
  signOut as fbSignOut,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  sendEmailVerification,
  sendPasswordResetEmail,
} from "https://www.gstatic.com/firebasejs/12.5.0/firebase-auth.js";
import {
  getFirestore,
  doc,
  getDoc,
  setDoc,
  collection,
  query,
  where,
  orderBy,
  getDocs,
  updateDoc,
  serverTimestamp,
} from "https://www.gstatic.com/firebasejs/12.5.0/firebase-firestore.js";

/* ================== FIREBASE SETUP ================== */

const firebaseConfig = {
  apiKey: "AIzaSyAI5lb0nXxAiBQThX6Y4tEQuqQ1cY6bn74",
  authDomain: "flying64th-b7813.firebaseapp.com",
  projectId: "flying64th-b7813",
  storageBucket: "flying64th-b7813.firebasestorage.app",
  messagingSenderId: "244940935157",
  appId: "1:244940935157:web:58e7305541377ba743dabc",
};

const app = getApps().length ? getApp() : initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

// Persist session across page loads/tabs for same origin
await setPersistence(auth, browserLocalPersistence);

/* ================== ROLE / PROFILE HELPERS ================== */

// Hard-coded admin UIDs (permanent full admins)
// TODO: replace these with your real admin UIDs
const ADMIN_UIDS = new Set([
  "ADMIN_UID_1",
  "ADMIN_UID_2",
  "ADMIN_UID_3",
  // "ADMIN_UID_4",
  // "ADMIN_UID_5",
]);

// Backwards-compat alias for any old code that imported OWNER_EMAILS
// (not actually used for logic anymore)
const OWNER_EMAILS = new Set();

/** Simple HTML escaper for safe rendering */
function escapeHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/** Load a profile doc from /profiles/{uid} */
async function getProfile(uid) {
  if (!uid) return null;
  try {
    const snap = await getDoc(doc(db, "profiles", uid));
    return snap.exists() ? snap.data() : null;
  } catch (err) {
    console.error("getProfile error:", err);
    return null;
  }
}

/**
 * Get the current user's role info.
 * Returns:
 *   { uid, email, role, isAdmin, isMember, profile }
 */
async function getMyRole() {
  const user = auth.currentUser;
  if (!user) {
    return {
      uid: null,
      email: null,
      role: null,
      isAdmin: false,
      isMember: false,
      profile: null,
    };
  }

  const profile = await getProfile(user.uid);
  let role = (profile?.role || "").toLowerCase();

  // Default to "member" if role is missing or junk
  if (role !== "admin" && role !== "member") {
    role = "member";
  }

  const email = profile?.email || user.email || null;

  // Admin if either explicitly admin in profile OR UID is in the hard-coded set
  const isAdminUID = ADMIN_UIDS.has(user.uid);
  const isAdminRole = role === "admin";
  const isAdmin = isAdminUID || isAdminRole;

  const isMember = !isAdmin && role === "member";

  return {
    uid: user.uid,
    email,
    role,
    isAdmin,
    isMember,
    profile: profile || {},
  };
}

/**
 * Require an active, verified member.
 * Uses:
 *  - user.emailVerified
 *  - /profiles/{uid}.active === true
 *
 * Returns:
 *   { ok:true, profile } OR { ok:false, reason:"verify"|"inactive" }
 */
async function requireActiveMember(user) {
  const u = user || auth.currentUser;
  if (!u) return { ok: false, reason: "verify" };
  if (!u.emailVerified) return { ok: false, reason: "verify" };

  const profile = await getProfile(u.uid);
  if (!profile || profile.active !== true) {
    return { ok: false, reason: "inactive" };
  }

  return { ok: true, profile };
}

/* ============= MEMBER LISTING (from /profiles) ============= */

/**
 * Fetch member profiles from /profiles.
 * filter: "active" | "disabled" | "all"
 * Returns array [{ uid, ...profileData }]
 */
async function fetchMembers(filter) {
  const colRef = collection(db, "profiles");

  const toList = async (q) =>
    (await getDocs(q)).docs.map((d) => ({ uid: d.id, ...d.data() }));

  try {
    if (filter === "active") {
      return await toList(
        query(
          colRef,
          where("active", "==", true),
          orderBy("lastName"),
          orderBy("firstName")
        )
      );
    } else if (filter === "disabled") {
      return await toList(
        query(
          colRef,
          where("active", "==", false),
          orderBy("lastName"),
          orderBy("firstName")
        )
      );
    } else {
      return await toList(
        query(colRef, orderBy("lastName"), orderBy("firstName"))
      );
    }
  } catch (err) {
    console.warn("fetchMembers fallback:", err);
    // Fallback without index
    const snap = await getDocs(colRef);
    let arr = snap.docs.map((d) => ({ uid: d.id, ...d.data() }));
    if (filter === "active") {
      arr = arr.filter((x) => x.active === true);
    } else if (filter === "disabled") {
      arr = arr.filter((x) => x.active === false);
    }
    arr.sort((a, b) =>
      `${a.lastName || ""} ${a.firstName || ""}`.localeCompare(
        `${b.lastName || ""} ${b.firstName || ""}`
      )
    );
    return arr;
  }
}

/** Toggle active status on /profiles/{uid} */
async function toggleMemberActive(uid, desired) {
  if (!uid) throw new Error("Missing uid.");
  await updateDoc(doc(db, "profiles", uid), {
    active: desired,
    updatedAt: serverTimestamp(),
  });
}

/** Wrapper for onAuthStateChanged */
function onAuthChanged(cb) {
  return onAuthStateChanged(auth, cb);
}

/* ================== INVITE LOGIC ================== */
/**
 * Validate the permanent invite code in Firestore.
 * Firestore doc: invites/primary => { enabled:true, code:"F64-..." }
 */
async function validateInvite(inputCode) {
  const code = (inputCode || "").trim();
  if (!code) return { ok: false, msg: "Invite code required." };

  const ref = doc(db, "invites", "primary");
  const snap = await getDoc(ref);
  if (!snap.exists()) return { ok: false, msg: "Invite not found." };

  const d = snap.data();
  const enabled = d.enabled !== false; // default true
  const serverCode = String(d.code || "").trim();

  if (!enabled) return { ok: false, msg: "Sign-ups are disabled." };
  if (code !== serverCode) return { ok: false, msg: "Invalid invite code." };

  // Reusable forever — no 'used' tracking.
  return { ok: true, ref };
}

/* ================== PROFILE CREATION ================== */

/**
 * Ensure /profiles/{uid} exists for a new user.
 * New users default to role "member".
 */
async function ensureProfileDocs(uid, email, firstName, lastName) {
  const base = {
    uid,
    email,
    firstName,
    lastName,
    emailVerified: false,
    active: true,
    role: "member", // only "admin" or "member" now; new signups are members
    createdAt: serverTimestamp(),
    updatedAt: serverTimestamp(),
  };

  await setDoc(doc(db, "profiles", uid), base, { merge: true });
}

/* ================== AUTH HELPERS ================== */

/** Sign in (email/password) */
async function signInEmailPassword(email, password) {
  const e = (email || "").trim();
  const p = password || "";
  if (!e || !p) throw new Error("Enter email and password.");
  const cred = await signInWithEmailAndPassword(auth, e, p);
  return cred.user;
}

/**
 * Sign up with permanent invite (requires first/last names).
 * Creates profile doc in /profiles with role "member".
 */
async function signUpWithInvite({ email, password, firstName, lastName, code }) {
  const e = (email || "").trim();
  const p = password || "";
  const f = (firstName || "").trim();
  const l = (lastName || "").trim();
  const c = (code || "").trim();

  if (!e || !p || !f || !l || !c) {
    throw new Error(
      "First name, last name, email, password, and invite code are required."
    );
  }

  const iv = await validateInvite(c);
  if (!iv.ok) throw new Error(iv.msg || "Invalid invite.");

  const cred = await createUserWithEmailAndPassword(auth, e, p);

  // Create Firestore profile
  await ensureProfileDocs(cred.user.uid, e, f, l);

  // Send verification (non-blocking)
  try {
    await sendEmailVerification(cred.user);
  } catch (err) {
    console.warn("sendEmailVerification failed:", err);
  }

  return cred.user;
}

/** Reset password */
async function resetPassword(email) {
  const e = (email || "").trim();
  if (!e) throw new Error("Enter your email first.");
  await sendPasswordResetEmail(auth, e);
  return true;
}

/** Re-send verification email */
async function resendVerification() {
  const u = auth.currentUser;
  if (!u) throw new Error("Not signed in.");
  await sendEmailVerification(u);
  return true;
}

/** Sign out */
async function signOut() {
  await fbSignOut(auth);
}

/* ================== EXPORTS ================== */

export {
  app,
  auth,
  db,

  // State & roles
  onAuthChanged,
  getMyRole,
  requireActiveMember,

  // Members directory helpers (now based on /profiles)
  fetchMembers,
  toggleMemberActive,
  getProfile,

  // Auth helpers
  signInEmailPassword,
  signUpWithInvite,
  resetPassword,
  resendVerification,
  signOut,

  // Misc
  escapeHtml,
  ADMIN_UIDS,
  OWNER_EMAILS, // legacy/no-op but exported in case something still imports it
  validateInvite,
  ensureProfileDocs,
};
