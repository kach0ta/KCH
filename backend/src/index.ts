export interface Env { DB: D1Database; APP_ENV?: string; }
type User = { id:string; username:string; display_name:string; password_hash?:string; password_salt?:string };
const H = { "content-type":"application/json; charset=utf-8", "cache-control":"no-store" };
const now = () => Math.floor(Date.now()/1000);
const out = (v:unknown,s=200) => new Response(JSON.stringify(v),{status:s,headers:H});
const err = (e:string,s=400) => out({error:e},s);
const enc = new TextEncoder();
const hex = (b:ArrayBuffer) => [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("");
const token = (n=32) => { const b=new Uint8Array(n); crypto.getRandomValues(b); return btoa(String.fromCharCode(...b)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,""); };
const sha = async (s:string) => hex(await crypto.subtle.digest("SHA-256",enc.encode(s)));
async function passHash(p:string,s:string) {
 const k=await crypto.subtle.importKey("raw",enc.encode(p),"PBKDF2",false,["deriveBits"]);
 return hex(await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:enc.encode(s),iterations:310000},k,256));
}
async function data(r:Request):Promise<any>{try{return await r.json()}catch{return null}}
async function current(r:Request,e:Env):Promise<User|null>{
 const t=r.headers.get("authorization")?.replace(/^Bearer\s+/i,""); if(!t)return null;
 return await e.DB.prepare("SELECT u.id,u.username,u.display_name FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND u.disabled_at IS NULL").bind(await sha(t),now()).first<User>();
}
async function session(e:Env,id:string){const t=token();await e.DB.prepare("INSERT INTO sessions(id,user_id,token_hash,created_at,expires_at) VALUES(?,?,?,?,?)").bind(crypto.randomUUID(),id,await sha(t),now(),now()+2592000).run();return t;}
export default { async fetch(r:Request,e:Env):Promise<Response>{
 const u=new URL(r.url), p=u.pathname;
 if(r.method==="GET"&&p==="/health")return out({ok:true,service:"kch-api",public:true});
 if(r.method==="POST"&&p==="/v1/auth/register"){
  const d=await data(r); if(!d||typeof d.username!=="string"||!/^[a-zA-Z0-9_]{3,24}$/.test(d.username)||typeof d.password!=="string"||d.password.length<6||d.password.length>128)return err("invalid_registration_data");
  const name=d.username.toLowerCase(); if(await e.DB.prepare("SELECT id FROM users WHERE username=?").bind(name).first())return err("username_taken",409);
  const id=crypto.randomUUID(), salt=token(16), hash=await passHash(d.password,salt);
  try{await e.DB.prepare("INSERT INTO users(id,username,password_hash,password_salt,display_name,created_at) VALUES(?,?,?,?,?,?)").bind(id,name,hash,salt,name,now()).run()}catch{return err("could_not_create_account",409)}
  return out({token:await session(e,id),user:{id,username:name,displayName:name}},201);
 }
 if(r.method==="POST"&&p==="/v1/auth/login"){
  const d=await data(r);if(!d||typeof d.username!=="string"||typeof d.password!=="string")return err("credentials_required");
  const x=await e.DB.prepare("SELECT id,username,display_name,password_hash,password_salt FROM users WHERE username=? AND disabled_at IS NULL").bind(d.username.toLowerCase()).first<User>();
  if(!x||await passHash(d.password,x.password_salt!)!==x.password_hash)return err("invalid_credentials",401);
  return out({token:await session(e,x.id),user:{id:x.id,username:x.username,displayName:x.display_name}});
 }
 const me=await current(r,e);if(!me)return err("unauthorized",401);
 if(r.method==="GET"&&p==="/v1/me")return out({id:me.id,username:me.username,displayName:me.display_name});
 if(r.method==="GET"&&p==="/v1/conversations"){
  const q=await e.DB.prepare("SELECT c.id,c.kind,c.title,c.created_at,m.role FROM conversation_members m JOIN conversations c ON c.id=m.conversation_id WHERE m.user_id=? ORDER BY c.created_at DESC LIMIT 100").bind(me.id).all();
  return out({conversations:q.results||[]});
 }
 if(r.method==="POST"&&p==="/v1/conversations"){
  const d=await data(r);if(!d||!["direct","group","channel"].includes(d.kind))return err("invalid_kind");
  const raw=Array.isArray(d.members)?d.members.filter((x:any)=>typeof x==="string").slice(0,49):[];
  const members=[...new Set([me.id,...raw])];if(d.kind==="direct"&&members.length!==2)return err("direct_chat_requires_two_members");
  const marks=members.map(()=>"?").join(",");
  const found=await e.DB.prepare("SELECT id FROM users WHERE disabled_at IS NULL AND id IN ("+marks+")").bind(...members).all<{id:string}>();
  if((found.results||[]).length!==members.length)return err("unknown_member",404);
  const id=crypto.randomUUID(),title=typeof d.title==="string"?d.title.slice(0,80):null;
  await e.DB.prepare("INSERT INTO conversations(id,kind,title,owner_user_id,created_at) VALUES(?,?,?,?,?)").bind(id,d.kind,title,me.id,now()).run();
  for(const uid of members)await e.DB.prepare("INSERT INTO conversation_members(conversation_id,user_id,role,joined_at) VALUES(?,?,?,?)").bind(id,uid,uid===me.id?"owner":"member",now()).run();
  return out({id,kind:d.kind,title},201);
 }
 const m=p.match(/^\/v1\/conversations\/([0-9a-f-]+)\/messages$/i);
 if(m){
  const cid=m[1],member=await e.DB.prepare("SELECT 1 FROM conversation_members WHERE conversation_id=? AND user_id=?").bind(cid,me.id).first();
  if(!member)return err("not_found",404);
  if(r.method==="GET"){const q=await e.DB.prepare("SELECT id,sender_user_id,ciphertext,created_at FROM messages WHERE conversation_id=? ORDER BY created_at DESC LIMIT 100").bind(cid).all();return out({messages:(q.results||[]).reverse()});}
  if(r.method==="POST"){const d=await data(r);if(!d||typeof d.ciphertext!=="string"||d.ciphertext.length<16||d.ciphertext.length>20000)return err("ciphertext_required");const id=crypto.randomUUID();await e.DB.prepare("INSERT INTO messages(id,conversation_id,sender_user_id,ciphertext,created_at) VALUES(?,?,?,?,?)").bind(id,cid,me.id,d.ciphertext,now()).run();return out({id,createdAt:now()},201);}
 }
 return err("not_found",404);
}};
