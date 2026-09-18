import 'dotenv/config';
import express from 'express';
import path from 'node:path';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import Stripe from 'stripe';
import multer from 'multer';
import cookieParser from 'cookie-parser';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 3000);
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const DATA_DIR = path.join(__dirname, 'data');
const PRIVATE_DIR = path.join(__dirname, 'private', 'downloads');
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(PRIVATE_DIR, { recursive: true });
const DB_FILE = path.join(DATA_DIR, 'db.json');
const stripe = process.env.STRIPE_SECRET_KEY?.startsWith('sk_') ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';

const initialProducts = [
  { id:'e1', type:'ebook', title:'+5000 fournisseurs POWER', price:80, category:'Business', description:'Un répertoire numérique de fournisseurs à exploiter avec méthode et prudence.', file:'e1.pdf', active:true },
  { id:'e2', type:'ebook', title:'BadBoyVF', price:25, category:'Développement personnel', description:'Un guide autour de la confiance en soi, des relations et du développement personnel.', file:'e2.pdf', active:true },
  { id:'e3', type:'ebook', title:'E-book Vinted', price:120, category:'Resell', description:'Un guide consacré à la vente sur les plateformes de seconde main.', file:'e3.pdf', active:true },
  { id:'e4', type:'ebook', title:'Resell Vinted', price:80, category:'Resell', description:'Méthodes et repères pour structurer une activité d’achat-revente.', file:'e4.pdf', active:true },
  { id:'e5', type:'ebook', title:'Tech Sneakers', price:65, category:'Sneakers', description:'Guide consacré à l’univers des sneakers et aux méthodes de revente.', file:'e5.pdf', active:false }
];

function loadDb(){
  if(!fs.existsSync(DB_FILE)){ const db={users:[],products:initialProducts,orders:[],entitlements:[]}; fs.writeFileSync(DB_FILE,JSON.stringify(db,null,2)); return db; }
  const db=JSON.parse(fs.readFileSync(DB_FILE,'utf8'));
  db.products ??= initialProducts; db.users ??=[]; db.orders ??=[]; db.entitlements ??=[]; return db;
}
let db=loadDb();
const saveDb=()=>fs.writeFileSync(DB_FILE,JSON.stringify(db,null,2));
const uid=()=>crypto.randomUUID();
function hashPassword(password,salt=crypto.randomBytes(16).toString('hex')){return `${salt}:${crypto.scryptSync(password,salt,64).toString('hex')}`;}
function verifyPassword(password,stored){try{const [salt,hash]=String(stored).split(':');const candidate=crypto.scryptSync(password,salt,64).toString('hex');return crypto.timingSafeEqual(Buffer.from(candidate,'hex'),Buffer.from(hash,'hex'));}catch{return false;}}
function currentUser(req){const token=req.cookies?.novalife_session;return token?db.users.find(u=>u.sessionToken===token)||null:null;}
function requireUser(req,res,next){const user=currentUser(req);if(!user)return res.status(401).json({error:'Connexion requise'});req.user=user;next();}
function requireAdmin(req,res,next){if(!ADMIN_TOKEN||req.headers.authorization!==`Bearer ${ADMIN_TOKEN}`)return res.status(401).json({error:'Accès administrateur refusé'});next();}
const publicUser=u=>u?{id:u.id,email:u.email,name:u.name}:null;
const publicProduct=p=>({...p,file:undefined});

app.post('/api/stripe/webhook',express.raw({type:'application/json'}),async(req,res)=>{
  if(!stripe||!process.env.STRIPE_WEBHOOK_SECRET)return res.status(503).send('Webhook non configuré');
  let event; try{event=stripe.webhooks.constructEvent(req.body,req.headers['stripe-signature'],process.env.STRIPE_WEBHOOK_SECRET);}catch(e){return res.status(400).send(`Signature invalide: ${e.message}`);}
  if(event.type==='checkout.session.completed'){
    const s=event.data.object; if(db.orders.some(o=>o.stripeSessionId===s.id))return res.json({received:true});
    const productIds=(s.metadata?.productIds||'').split(',').filter(Boolean); const orderId=uid();
    db.orders.push({id:orderId,userId:s.metadata?.userId||null,stripeSessionId:s.id,amount:s.amount_total||0,status:'paid',createdAt:new Date().toISOString(),productIds});
    for(const productId of productIds)db.entitlements.push({id:uid(),userId:s.metadata?.userId||null,productId,orderId});
    saveDb();
  }
  res.json({received:true});
});

app.use(cookieParser());
app.use(express.json({limit:'2mb'}));
app.use(express.static(path.join(__dirname,'public')));

app.get('/api/products',(req,res)=>res.json(db.products.filter(p=>p.active).map(publicProduct)));
app.get('/api/products/all',requireAdmin,(req,res)=>res.json(db.products.map(publicProduct)));
app.get('/api/products/:id',(req,res)=>{const p=db.products.find(x=>x.id===req.params.id&&x.active);if(!p)return res.status(404).json({error:'Produit introuvable'});res.json(publicProduct(p));});

app.post('/api/auth/register',(req,res)=>{const {email,password,name=''}=req.body||{};if(!/^\S+@\S+\.\S+$/.test(email||'')||typeof password!=='string'||password.length<8)return res.status(400).json({error:'E-mail invalide ou mot de passe trop court (8 caractères minimum).'});if(db.users.some(u=>u.email===email.toLowerCase()))return res.status(409).json({error:'Ce compte existe déjà.'});const user={id:uid(),email:email.toLowerCase(),name,passwordHash:hashPassword(password),sessionToken:crypto.randomBytes(32).toString('hex'),createdAt:new Date().toISOString()};db.users.push(user);saveDb();res.cookie('novalife_session',user.sessionToken,{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:2592000000});res.status(201).json({user:publicUser(user)});});
app.post('/api/auth/login',(req,res)=>{const {email,password}=req.body||{};const user=db.users.find(u=>u.email===String(email||'').toLowerCase());if(!user||!verifyPassword(password||'',user.passwordHash))return res.status(401).json({error:'Identifiants incorrects.'});user.sessionToken=crypto.randomBytes(32).toString('hex');saveDb();res.cookie('novalife_session',user.sessionToken,{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:2592000000});res.json({user:publicUser(user)});});
app.post('/api/auth/logout',(req,res)=>{const u=currentUser(req);if(u){u.sessionToken=null;saveDb();}res.clearCookie('novalife_session');res.json({ok:true});});
app.get('/api/me',(req,res)=>res.json({user:publicUser(currentUser(req))}));
app.get('/api/account',requireUser,(req,res)=>{const orders=db.orders.filter(o=>o.userId===req.user.id).map(o=>({...o,products:o.productIds.map(id=>db.products.find(p=>p.id===id)?.title||id)}));const library=db.entitlements.filter(e=>e.userId===req.user.id).map(e=>{const p=db.products.find(p=>p.id===e.productId);return {entitlementId:e.id,productId:e.productId,title:p?.title,downloadable:Boolean(p?.file&&fs.existsSync(path.join(PRIVATE_DIR,p.file)))};});res.json({user:publicUser(req.user),orders,library});});

app.post('/api/create-checkout-session',requireUser,async(req,res)=>{try{const ids=Array.isArray(req.body?.productIds)?[...new Set(req.body.productIds)]:[];const selected=ids.map(id=>db.products.find(p=>p.id===id)).filter(Boolean);if(!selected.length)return res.status(400).json({error:'Panier vide'});if(selected.some(p=>!p.active))return res.status(403).json({error:'Un produit du panier n’est pas disponible.'});if(!stripe)return res.status(503).json({error:'Stripe non configuré. Ajoute STRIPE_SECRET_KEY dans .env.'});const session=await stripe.checkout.sessions.create({mode:'payment',customer_email:req.user.email,line_items:selected.map(p=>({price_data:{currency:'eur',product_data:{name:p.title,description:p.description},unit_amount:Math.round(p.price*100)},quantity:1})),success_url:`${BASE_URL}/?payment=success`,cancel_url:`${BASE_URL}/?payment=cancelled`,metadata:{userId:req.user.id,productIds:selected.map(p=>p.id).join(',')}});res.json({url:session.url});}catch(e){console.error(e);res.status(500).json({error:'Impossible de créer la session Stripe.'});}});

app.get('/api/download/:entitlementId',requireUser,(req,res)=>{const e=db.entitlements.find(x=>x.id===req.params.entitlementId&&x.userId===req.user.id);if(!e)return res.status(404).json({error:'Accès introuvable'});const p=db.products.find(x=>x.id===e.productId);if(!p?.file)return res.status(404).json({error:'Fichier indisponible'});const filePath=path.join(PRIVATE_DIR,p.file);if(!fs.existsSync(filePath))return res.status(404).json({error:'Fichier non installé sur le serveur'});res.download(filePath,p.file);});

const upload=multer({dest:path.join(DATA_DIR,'uploads'),limits:{fileSize:100*1024*1024},fileFilter:(req,file,cb)=>cb(null,file.mimetype==='application/pdf')});
app.post('/api/admin/products',requireAdmin,(req,res)=>{const {title,type='ebook',price,category='',description=''}=req.body||{};if(!title||!Number.isFinite(Number(price)))return res.status(400).json({error:'Titre et prix requis'});const p={id:uid(),title,type,price:Number(price),category,description,file:null,active:false};db.products.push(p);saveDb();res.status(201).json(publicProduct(p));});
app.patch('/api/admin/products/:id',requireAdmin,(req,res)=>{const p=db.products.find(x=>x.id===req.params.id);if(!p)return res.status(404).json({error:'Produit introuvable'});for(const k of ['title','type','category','description','price','active'])if(k in req.body)p[k]=k==='price'?Number(req.body[k]):req.body[k];saveDb();res.json(publicProduct(p));});
app.post('/api/admin/products/:id/file',requireAdmin,upload.single('pdf'),(req,res)=>{const p=db.products.find(x=>x.id===req.params.id);if(!p||!req.file)return res.status(400).json({error:'Produit ou PDF invalide'});const target=path.join(PRIVATE_DIR,`${p.id}.pdf`);fs.renameSync(req.file.path,target);p.file=`${p.id}.pdf`;saveDb();res.json({ok:true,product:publicProduct(p)});});
app.get('/api/admin/stats',requireAdmin,(req,res)=>res.json({users:db.users.length,products:db.products.length,activeProducts:db.products.filter(p=>p.active).length,orders:db.orders.length,revenue:db.orders.filter(o=>o.status==='paid').reduce((s,o)=>s+o.amount,0)/100}));

app.get('*',(_req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT,()=>console.log(`NovaLife lancé sur ${BASE_URL}`));
