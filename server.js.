import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import pg from 'pg';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const { Pool } = pg;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 3000);
const pool = process.env.DATABASE_URL ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized:false } }) : null;
const memoryUsers = new Map();
const memorySessions = new Map();
const memoryData = new Map();

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy:false }));
app.use(express.json({ limit:'1mb' }));
app.use(cookieParser());
app.use(rateLimit({ windowMs:15*60*1000, limit:300, standardHeaders:true, legacyHeaders:false }));
app.use(express.static(path.join(__dirname,'public')));

const defaultData = () => ({
  products:[{id:'demo-1',name:'Produto demonstração',sku:'DEMO-001',cost:20,sale:49.9,stock:20,image:'',supplierId:''}],
  orders:[], customers:[], suppliers:[], marketplaces:[
    {id:'ml',name:'Mercado Livre',type:'marketplace',status:'available'},
    {id:'shopee',name:'Shopee',type:'marketplace',status:'available'},
    {id:'bling',name:'Bling',type:'erp',status:'available'}
  ],
  finance:[], settings:{storeName:'DropPro'}
});

async function db(q, params=[]){ if(!pool) return null; return pool.query(q,params); }
async function initDb(){
  if(!pool) return;
  await pool.query(`CREATE TABLE IF NOT EXISTS users(id UUID PRIMARY KEY,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,created_at TIMESTAMPTZ DEFAULT NOW());
  CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires_at TIMESTAMPTZ NOT NULL);
  CREATE TABLE IF NOT EXISTS user_data(user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,data JSONB NOT NULL DEFAULT '{}'::jsonb);
  CREATE TABLE IF NOT EXISTS integrations(user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,provider TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'disconnected',account JSONB DEFAULT '{}'::jsonb,updated_at TIMESTAMPTZ DEFAULT NOW(),PRIMARY KEY(user_id,provider));`);
  const hash=await bcrypt.hash(process.env.DEMO_PASSWORD || 'DropPro@2026!',12);
  const id=crypto.randomUUID();
  await pool.query(`INSERT INTO users(id,email,password_hash) VALUES($1,$2,$3) ON CONFLICT(email) DO NOTHING`,[id,'demo@droppro.app',hash]);
  const u=await pool.query('SELECT id FROM users WHERE email=$1',['demo@droppro.app']);
  await pool.query(`INSERT INTO user_data(user_id,data) VALUES($1,$2) ON CONFLICT(user_id) DO NOTHING`,[u.rows[0].id,JSON.stringify(defaultData())]);
}
function cookieOptions(){return {httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:7*24*60*60*1000,path:'/'};}
async function getUser(req){
  const token=req.cookies.droppro_session; if(!token) return null;
  if(pool){const r=await db('SELECT u.id,u.email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=$1 AND s.expires_at>NOW()',[token]);return r?.rows[0]||null;}
  const s=memorySessions.get(token); return s&&s.expires>Date.now()?memoryUsers.get(s.userId):null;
}
async function requireAuth(req,res,next){req.user=await getUser(req);if(!req.user)return res.status(401).json({error:'Não autenticado'});next();}
async function readData(userId){if(pool){const r=await db('SELECT data FROM user_data WHERE user_id=$1',[userId]);return r?.rows[0]?.data||defaultData();}return memoryData.get(userId)||defaultData();}
async function writeData(userId,data){if(pool){await db('INSERT INTO user_data(user_id,data) VALUES($1,$2) ON CONFLICT(user_id) DO UPDATE SET data=EXCLUDED.data',[userId,JSON.stringify(data)]);}else memoryData.set(userId,data);return data;}

app.get('/api/health',(req,res)=>res.json({ok:true,service:'DropPro',version:'2.0.0'}));
app.post('/api/auth/signup',async(req,res)=>{try{const email=String(req.body.email||'').trim().toLowerCase(),password=String(req.body.password||'');if(!/^\S+@\S+\.\S+$/.test(email)||password.length<8)return res.status(400).json({error:'Informe um e-mail válido e senha com pelo menos 8 caracteres.'});if(pool){const exists=await db('SELECT 1 FROM users WHERE email=$1',[email]);if(exists.rows.length)return res.status(409).json({error:'E-mail já cadastrado.'});const id=crypto.randomUUID(),hash=await bcrypt.hash(password,12);await db('INSERT INTO users(id,email,password_hash) VALUES($1,$2,$3)',[id,email,hash]);await db('INSERT INTO user_data(user_id,data) VALUES($1,$2)',[id,JSON.stringify(defaultData())]);return loginUser(res,{id,email});}const id=crypto.randomUUID();if(memoryUsers.has(email))return res.status(409).json({error:'E-mail já cadastrado.'});memoryUsers.set(email,{id,email,passwordHash:await bcrypt.hash(password,12)});memoryData.set(id,defaultData());return loginUser(res,memoryUsers.get(email));}catch(e){res.status(500).json({error:'Falha ao criar conta.'});}});
async function loginUser(res,user){const token=crypto.randomBytes(32).toString('hex'),expires=Date.now()+7*24*60*60*1000;if(pool)await db('INSERT INTO sessions(token,user_id,expires_at) VALUES($1,$2,NOW()+INTERVAL \'7 days\')',[token,user.id]);else memorySessions.set(token,{userId:user.id,expires});res.cookie('droppro_session',token,cookieOptions());res.json({user:{id:user.id,email:user.email}});}
app.post('/api/auth/login',async(req,res)=>{const email=String(req.body.email||'').trim().toLowerCase(),password=String(req.body.password||'');if(pool){const r=await db('SELECT id,email,password_hash FROM users WHERE email=$1',[email]);if(!r?.rows[0]||!(await bcrypt.compare(password,r.rows[0].password_hash)))return res.status(401).json({error:'E-mail ou senha inválidos.'});return loginUser(res,r.rows[0]);}const u=memoryUsers.get(email);if(!u||!(await bcrypt.compare(password,u.passwordHash)))return res.status(401).json({error:'E-mail ou senha inválidos.'});return loginUser(res,u);});
app.post('/api/auth/logout',async(req,res)=>{const token=req.cookies.droppro_session;if(token){if(pool)await db('DELETE FROM sessions WHERE token=$1',[token]);else memorySessions.delete(token);}res.clearCookie('droppro_session');res.json({ok:true});});
app.get('/api/auth/me',async(req,res)=>{const u=await getUser(req);res.json({user:u?{id:u.id,email:u.email}:null});});
app.get('/api/data',requireAuth,async(req,res)=>res.json(await readData(req.user.id)));
app.put('/api/data',requireAuth,async(req,res)=>res.json(await writeData(req.user.id,req.body)));
app.get('/api/dashboard',requireAuth,async(req,res)=>{const d=await readData(req.user.id);res.json({products:d.products.length,orders:d.orders.length,revenue:d.orders.reduce((s,o)=>s+Number(o.amount||o.total||0),0),customers:d.customers.length,suppliers:d.suppliers.length});});
app.get('/api/integrations/status',requireAuth,async(req,res)=>{if(pool){const r=await db('SELECT provider,status,account,updated_at FROM integrations WHERE user_id=$1',[req.user.id]);return res.json(r.rows);}res.json([{provider:'mercadolivre',status:'disconnected'},{provider:'shopee',status:'disconnected'},{provider:'bling',status:'disconnected'}]);});

app.get('/oauth/mercadolivre/start',requireAuth,(req,res)=>{const client=process.env.ML_CLIENT_ID;if(!client)return res.status(503).send('Configure ML_CLIENT_ID no ambiente.');const state=crypto.randomBytes(24).toString('hex');res.cookie('ml_oauth_state',state,{...cookieOptions(),maxAge:10*60*1000});const u=new URL('https://auth.mercadolivre.com.br/authorization');u.searchParams.set('response_type','code');u.searchParams.set('client_id',client);u.searchParams.set('redirect_uri',process.env.ML_REDIRECT_URI||`${process.env.BASE_URL}/oauth/mercadolivre/callback`);u.searchParams.set('state',state);res.redirect(u.toString());});
app.get('/oauth/mercadolivre/callback',async(req,res)=>{res.send('Mercado Livre: callback recebido. Configure as credenciais OAuth no servidor para concluir a troca do código por token.');});
app.get('/oauth/bling/start',requireAuth,(req,res)=>{const client=process.env.BLING_CLIENT_ID;if(!client)return res.status(503).send('Configure BLING_CLIENT_ID no ambiente.');const u=new URL('https://www.bling.com.br/Api/v3/oauth/authorize');u.searchParams.set('response_type','code');u.searchParams.set('client_id',client);u.searchParams.set('state',crypto.randomBytes(16).toString('hex'));u.searchParams.set('redirect_uri',process.env.BLING_REDIRECT_URI||`${process.env.BASE_URL}/oauth/bling/callback`);res.redirect(u.toString());});
app.get('/oauth/bling/callback',(req,res)=>res.send('Bling: callback recebido. Configure as credenciais OAuth no servidor para concluir a troca do código por token.'));

app.use((req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
initDb().then(()=>app.listen(PORT,()=>console.log(`DropPro rodando na porta ${PORT}`))).catch(e=>{console.error(e);process.exit(1)});
