// auth.js (Firebase v12.5.0) — unified auth helpers with reusable invite code
import { initializeApp, getApps, getApp } from "https://www.gstatic.com/firebasejs/12.5.0/firebase-app.js";
import {
  getAuth, onAuthStateChanged, setPersistence, browserLocalPersistence, signOut as fbSignOut,
  createUserWithEmailAndPassword, signInWithEmailAndPassword,
  sendEmailVerification, sendPasswordResetEmail
} from "https://www.gstatic.com/firebasejs/12.5.0/firebase-auth.js";
import {
  getFirestore, doc, getDoc, setDoc, collection, query, where, orderBy, getDocs,
  updateDoc, serverTimestamp
} from "https://www.gstatic.com/firebasejs/12.5.0/firebase-firestore.js";

// === Firebase config (public client keys) ===
const firebaseConfig = {
  apiKey: "AIzaSyAI5lb0nXxAiBQThX6Y4tEQuqQ1cY6bn74",
  authDomain: "flying64th-b7813.firebaseapp.com",
  projectId: "flying64th-b7813",
  storageBucket: "flying64th-b7813.firebasestorage.app",
  messagingSenderId: "244940935157",
  appId: "1:244940935157:web:58e7305541377ba743dabc"
};

const app  = getApps().length ? getApp() : initializeApp(firebaseConfig);
const auth = getAuth(app);
const db   = getFirestore(app);

// Persist session across page loads/tabs for same origin
await setPersistence(auth, browserLocalPersistence);

// Owner emails (mirrors your rules’ “owner” concept)
const OWNER_EMAILS = new Set(['theflying64@gmail.com','tristanstuff@denjess.com']);

// ------------------------
// Utilities & role helpers
// ------------------------
function escapeHtml(s){
  return String(s ?? "")
    .replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#039;");
}

async function getProfile(uid){
  try {
    const snap = await getDoc(doc(db, "profiles", uid));
    return snap.exists() ? snap.data() : null;
  } catch {
    return null;
  }
}

async function getMyRole(){
  const u = auth.currentUser;
  if (!u) return { role:null, email:null, isSuper:false, isAdmin:false, isOwner:false };
  const p = await getProfile(u.uid);
  const role  = (p?.role || "").toLowerCase();
  const email = p?.email || u.email || null;
  const isOwner = email ? OWNER_EMAILS.has(email) : false;
  const isSuper = isOwner || role === "superadmin";
  const isAdmin = isSuper || role === "admin";
  return { role, email, isSuper, isAdmin, isOwner };
}

// Gate = verified + active member in /members
async function requireActiveMember(user){
  if (!user?.emailVerified) return { ok:false, reason:"verify" };
  const msnap = await getDoc(doc(db, "members", user.uid));
  if (!msnap.exists() || msnap.data()?.active !== true) return { ok:false, reason:"inactive" };
  return { ok:true };
}

// Roster helpers (directory)
async function fetchMembers(filter){ // 'active' | 'disabled' | 'all'
  const col = collection(db, "members");
  const toList = async (q) => (await getDocs(q)).docs.map(d => ({ uid:d.id, ...d.data() }));
  try{
    if (filter === "active"){
      return await toList(query(col, where("active","==", true), orderBy("lastName"), orderBy("firstName")));
    } else if (filter === "disabled"){
      return await toList(query(col, where("active","==", false), orderBy("lastName"), orderBy("firstName")));
    } else {
      return await toList(query(col, orderBy("lastName"), orderBy("firstName")));
    }
  } catch {
    // Fallback without composite index (shouldn’t be needed with your indexes)
    const snap = await getDocs(col);
    let arr = snap.docs.map(d => ({ uid:d.id, ...d.data() }));
    if (filter !== "all") arr = arr.filter(x => !!x && (x.active === (filter === "active")));
    arr.sort((a,b)=>`${a.lastName||''} ${a.firstName||''}`.localeCompare(`${b.lastName||''} ${b.firstName||''}`));
    return arr;
  }
}

async function toggleMemberActive(uid, desired){
  await updateDoc(doc(db,"members",uid), { active: desired, updatedAt: serverTimestamp() });
}

function onAuthChanged(cb){ return onAuthStateChanged(auth, cb); }

// ---------------------------
// Sign-in / Sign-up utilities
// ---------------------------

// 1) Validate the permanent invite code in Firestore
//    Firestore doc: invites/primary  => { enabled:true, code:"F64-CHRIS-2025-9QK7ATJ3" }
async function validateInvite(inputCode){
  const code = (inputCode || "").trim();
  if (!code) return { ok:false, msg:"Invite code required." };

  const ref = doc(db, "invites", "primary");
  const snap = await getDoc(ref);
  if (!snap.exists()) return { ok:false, msg:"Invite not found." };

  const d = snap.data();
  const enabled = d.enabled !== false;     // default true
  const serverCode = String(d.code || "").trim();

  if (!enabled)               return { ok:false, msg:"Sign-ups are disabled." };
  if (code !== serverCode)    return { ok:false, msg:"Invalid invite code." };

  // Reusable forever — no 'used' tracking.
  return { ok:true, ref };
}

// 2) Create profile & member docs for a new user
async function ensureProfileDocs(uid, email, firstName, lastName){
  const base = {
    uid, email, firstName, lastName,
    emailVerified: false,
    active: true,
    role: "user",
    createdAt: serverTimestamp(),
    updatedAt: serverTimestamp()
  };
  await Promise.all([
    setDoc(doc(db, "profiles", uid), base, { merge:true }),
    setDoc(doc(db, "members",  uid), base, { merge:true }),
  ]);
}

// 3) Public helpers your pages can call

// Sign in (email/password only)
async function signInEmailPassword(email, password){
  const e = (email || "").trim();
  const p = password || "";
  if (!e || !p) throw new Error("Enter email and password.");
  const cred = await signInWithEmailAndPassword(auth, e, p);
  return cred.user;
}

// Sign up with permanent invite (requires first/last names)
async function signUpWithInvite({ email, password, firstName, lastName, code }){
  const e = (email || "").trim();
  const p = password || "";
  const f = (firstName || "").trim();
  const l = (lastName  || "").trim();
  const c = (code || "").trim();

  if (!e || !p || !f || !l || !c) {
    throw new Error("First name, last name, email, password, and invite code are required.");
  }

  const iv = await validateInvite(c);
  if (!iv.ok) throw new Error(iv.msg || "Invalid invite.");

  const cred = await createUserWithEmailAndPassword(auth, e, p);
  // Create Firestore docs immediately
  await ensureProfileDocs(cred.user.uid, e, f, l);
  // Send verification (non-blocking)
  try { await sendEmailVerification(cred.user); } catch(_) {}

  // Optional: you can log the attempt to /audit here if desired
  return cred.user;
}

// Reset password
async function resetPassword(email){
  const e = (email || "").trim();
  if (!e) throw new Error("Enter your email first.");
  await sendPasswordResetEmail(auth, e);
  return true;
}

// Re-send verification email (for UX flows)
async function resendVerification(){
  const u = auth.currentUser;
  if (!u) throw new Error("Not signed in.");
  await sendEmailVerification(u);
  return true;
}

// Sign out
async function signOut(){
  await fbSignOut(auth);
}

// -----------------
// Module exports
// -----------------
export {
  app, auth, db,

  // State & roles
  onAuthChanged, getMyRole, requireActiveMember,

  // Members directory helpers
  fetchMembers, toggleMemberActive, getProfile,

  // Auth helpers
  signInEmailPassword, signUpWithInvite, resetPassword, resendVerification, signOut,

  // Misc
  escapeHtml, OWNER_EMAILS,

  // Optional: expose validate for custom UIs
  validateInvite, ensureProfileDocs
};
