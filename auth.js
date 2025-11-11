// auth.js (Firebase v12.5.0)
import { initializeApp, getApps, getApp } from "https://www.gstatic.com/firebasejs/12.5.0/firebase-app.js";
import {
  getAuth, onAuthStateChanged, setPersistence, browserLocalPersistence, signOut
} from "https://www.gstatic.com/firebasejs/12.5.0/firebase-auth.js";
import {
  getFirestore, doc, getDoc, collection, query, where, orderBy, getDocs,
  updateDoc, serverTimestamp
} from "https://www.gstatic.com/firebasejs/12.5.0/firebase-firestore.js";

// EXACT SAME CONFIG AS home.html (public client keys)
const firebaseConfig = {
  apiKey: "AIzaSyAI5lb0nXxAiBQThX6Y4tEQuqQ1cY6bn74",
  authDomain: "flying64th-b7813.firebaseapp.com",
  projectId: "flying64th-b7813",
  storageBucket: "flying64th-b7813.firebasestorage.app",
  messagingSenderId: "244940935157",
  appId: "1:244940935157:web:58e7305541377ba743dabc"
};

const app = getApps().length ? getApp() : initializeApp(firebaseConfig);
const auth = getAuth(app);
const db   = getFirestore(app);

// Persist session across page loads/tabs for same origin
await setPersistence(auth, browserLocalPersistence);

// Owner emails (mirrors your rules’ isOwner())
const OWNER_EMAILS = new Set(['theflying64@gmail.com','tristanstuff@denjess.com']);

// --- helpers ---
function escapeHtml(s){
  return String(s ?? "")
    .replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#039;");
}

async function getProfile(uid){
  try { const snap = await getDoc(doc(db, "profiles", uid)); return snap.exists() ? snap.data() : null; }
  catch { return null; }
}

async function getMyRole(){
  const u = auth.currentUser;
  if (!u) return { role:null, email:null, isSuper:false, isAdmin:false, isOwner:false };
  const p = await getProfile(u.uid);
  const role = (p?.role || "").toLowerCase();
  const email = p?.email || u.email || null;
  const isOwner = email ? OWNER_EMAILS.has(email) : false;
  const isSuper = isOwner || role === "superadmin";
  const isAdmin = isSuper || role === "admin";
  return { role, email, isSuper, isAdmin, isOwner };
}

// Gate = verified + active member
async function requireActiveMember(user){
  if (!user?.emailVerified) return { ok:false, reason:"verify" };
  const msnap = await getDoc(doc(db, "members", user.uid));
  if (!msnap.exists() || msnap.data()?.active !== true) return { ok:false, reason:"inactive" };
  return { ok:true };
}

// Roster helpers (for later when you want the directory)
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
    // fallback without composite index
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

// One-liner subscription
function onAuthChanged(cb){ return onAuthStateChanged(auth, cb); }

export {
  app, auth, db,
  onAuthChanged, signOut,
  requireActiveMember, getMyRole,
  fetchMembers, toggleMemberActive,
  getProfile, escapeHtml, OWNER_EMAILS
};
