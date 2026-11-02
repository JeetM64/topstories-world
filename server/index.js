import 'dotenv/config'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import rateLimit from 'express-rate-limit'
import cookieParser from 'cookie-parser'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { z } from 'zod'
import { initializeDatabase, pool } from './db.js'

const app=express(),port=Number(process.env.PORT||3000)
const allowedOrigins=new Set(['http://localhost:5173','http://localhost:3000','http://127.0.0.1:3000',process.env.CORS_ORIGIN,process.env.CLIENT_ORIGIN,process.env.APP_CLIENT_ORIGIN].filter(Boolean))
const here=path.dirname(fileURLToPath(import.meta.url)),root=path.resolve(here,'..')
if(!process.env.JWT_SECRET||process.env.JWT_SECRET.length<32) throw new Error('JWT_SECRET must contain at least 32 characters. Copy .env.example and replace the placeholder with a random secret.')
app.disable('x-powered-by')
app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],imgSrc:["'self'",'https:','data:'],styleSrc:["'self'","'unsafe-inline'",'https://fonts.googleapis.com'],fontSrc:["'self'",'data:','https://fonts.gstatic.com'],connectSrc:["'self'",...allowedOrigins],scriptSrc:["'self'"]}}}))
app.use(cors({origin:(requestOrigin,callback)=>callback(null,requestOrigin&&allowedOrigins.has(requestOrigin)?requestOrigin:false),credentials:true,methods:['GET','POST','PATCH','DELETE','OPTIONS'],allowedHeaders:['Content-Type','Authorization'],maxAge:600}))
app.use(express.json({limit:'100kb'}));app.use(cookieParser())
app.use('/api',(req,res,next)=>{const source=req.get('origin');if(['POST','PATCH','DELETE'].includes(req.method)&&source&&!allowedOrigins.has(source))return res.status(403).json({error:'Request origin is not allowed.'});next()})
app.use('/api',rateLimit({windowMs:15*60*1000,limit:300,standardHeaders:'draft-8',legacyHeaders:false}))
const authLimit=rateLimit({windowMs:15*60*1000,limit:12,standardHeaders:'draft-8',legacyHeaders:false,message:{error:'Too many authentication attempts. Try again in 15 minutes.'}})
const cookieOptions={httpOnly:true,secure:process.env.COOKIE_SECURE==='true',sameSite:process.env.COOKIE_SAME_SITE||(process.env.COOKIE_SECURE==='true'?'none':'lax'),path:'/',maxAge:15*60*1000}
const signToken=user=>jwt.sign({sub:user.id,role:user.role,email:user.email},process.env.JWT_SECRET,{expiresIn:process.env.JWT_EXPIRES_IN||'15m',issuer:'topstories.world',audience:'topstories.world'})
function authenticate(req,res,next){const bearer=req.get('authorization')?.match(/^Bearer\s+(.+)$/i)?.[1],token=bearer||req.cookies?.tsw_access;if(!token)return res.status(401).json({error:'Sign in required.'});try{req.user=jwt.verify(token,process.env.JWT_SECRET,{issuer:'topstories.world',audience:'topstories.world'});next()}catch{return res.status(401).json({error:'Session expired. Please sign in again.'})}}
function optionalAuth(req,_res,next){const bearer=req.get('authorization')?.match(/^Bearer\s+(.+)$/i)?.[1],token=bearer||req.cookies?.tsw_access;if(token)try{req.user=jwt.verify(token,process.env.JWT_SECRET,{issuer:'topstories.world',audience:'topstories.world'})}catch{}next()}
const allowRoles=(...roles)=>(req,res,next)=>roles.includes(req.user?.role)?next():res.status(403).json({error:'Your account cannot perform this action.'})
const asyncRoute=fn=>(req,res,next)=>Promise.resolve(fn(req,res,next)).catch(next)
const publicUser=({id,email,display_name,role,bio,created_at})=>({id,email,name:display_name,role,bio,createdAt:created_at})
const articleOut=a=>({id:a.id,category:a.category,title:a.title,excerpt:a.excerpt,author:a.author,role:a.role,authorBio:a.author_bio||'',date:new Date(a.created_at).toLocaleDateString('en-US',{month:'long',day:'2-digit',year:'numeric'}),time:a.read_time,image:a.image,featured:a.featured,published:a.published,views:a.views,likes:a.likes_count||0,body:a.body,createdAt:a.created_at,sourceName:a.source_name||'',sourceUrl:a.source_url||'',sourceDate:a.source_published_at||null})
const signupSchema=z.object({email:z.string().email().max(254),password:z.string().min(12).max(128),name:z.string().trim().min(2).max(80)})
const loginSchema=z.object({email:z.string().email().max(254),password:z.string().min(1).max(128)})
const articleSchema=z.object({title:z.string().trim().min(8).max(180),category:z.enum(['World','Technology','Culture','Science','Opinion','Business','Lifestyle']),excerpt:z.string().trim().min(20).max(400),author:z.string().trim().min(2).max(100),role:z.string().trim().max(100).default('Staff Writer'),authorBio:z.string().trim().max(500).default(''),time:z.string().trim().max(40).default('5 min read'),image:z.string().url().max(1000),body:z.string().trim().min(40).max(50000),featured:z.boolean().default(false),published:z.boolean().default(false),sourceName:z.string().trim().max(120).default(''),sourceUrl:z.union([z.string().url().max(1000),z.literal('')]).default(''),sourceDate:z.union([z.string().date(),z.null()]).optional()})

app.get('/api/health',asyncRoute(async(_req,res)=>{await pool.query('SELECT 1');res.json({status:'ok',database:'connected'})}))
app.post('/api/auth/signup',authLimit,asyncRoute(async(req,res)=>{
  const input=signupSchema.parse(req.body),email=input.email.trim().toLowerCase(),hash=await bcrypt.hash(input.password,12)
  const {rows}=await pool.query('INSERT INTO users(email,password_hash,display_name) VALUES($1,$2,$3) RETURNING id,email,display_name,role,bio,created_at',[email,hash,input.name.trim()])
  const user=publicUser(rows[0]);res.cookie('tsw_access',signToken(user),cookieOptions).status(201).json({user})
}))
app.post('/api/auth/login',authLimit,asyncRoute(async(req,res)=>{
  const input=loginSchema.parse(req.body),{rows}=await pool.query('SELECT id,email,password_hash,display_name,role,bio,created_at FROM users WHERE email=$1',[input.email.trim().toLowerCase()])
  if(!rows[0]||!await bcrypt.compare(input.password,rows[0].password_hash))return res.status(401).json({error:'Email or password is incorrect.'})
  const user=publicUser(rows[0]);res.cookie('tsw_access',signToken(user),cookieOptions).json({user})
}))
app.post('/api/auth/logout',(_req,res)=>res.clearCookie('tsw_access',{...cookieOptions,maxAge:undefined}).json({ok:true}))
app.get('/api/auth/me',authenticate,asyncRoute(async(req,res)=>{const {rows}=await pool.query('SELECT id,email,display_name,role,bio,created_at FROM users WHERE id=$1',[req.user.sub]);if(!rows[0])return res.status(401).json({error:'Account no longer exists.'});res.json({user:publicUser(rows[0])})}))
app.patch('/api/auth/me',authenticate,asyncRoute(async(req,res)=>{const input=z.object({name:z.string().trim().min(2).max(80).optional(),bio:z.string().trim().max(500).optional()}).parse(req.body);const {rows}=await pool.query('UPDATE users SET display_name=COALESCE($2,display_name),bio=COALESCE($3,bio) WHERE id=$1 RETURNING id,email,display_name,role,bio,created_at',[req.user.sub,input.name,input.bio]);res.json({user:publicUser(rows[0])})}))

app.get('/api/articles',asyncRoute(async(req,res)=>{const params=[],where=["a.published=true"];if(req.query.category&&req.query.category!=='World'){params.push(String(req.query.category));where.push(`a.category=$${params.length}`)}if(req.query.q){params.push(`%${String(req.query.q).slice(0,120)}%`);where.push(`(a.title ILIKE $${params.length} OR a.excerpt ILIKE $${params.length} OR a.author ILIKE $${params.length} OR a.category ILIKE $${params.length})`)}const order=req.query.sort==='Trending'?'a.views DESC,a.created_at DESC':req.query.sort==='Popular'?'likes_count DESC,a.views DESC,a.created_at DESC':'a.created_at DESC';const {rows}=await pool.query(`SELECT a.*,(SELECT count(*)::int FROM likes l WHERE l.article_id=a.id) AS likes_count FROM articles a WHERE ${where.join(' AND ')} ORDER BY ${order} LIMIT 100`,params);res.json({articles:rows.map(articleOut)})}))
app.get('/api/articles/:id',asyncRoute(async(req,res)=>{const {rows}=await pool.query('SELECT * FROM articles WHERE id=$1 AND published=true',[req.params.id]);if(!rows[0])return res.status(404).json({error:'Story not found.'});res.json({article:articleOut(rows[0])})}))
app.post('/api/articles/:id/view',optionalAuth,asyncRoute(async(req,res)=>{const {rows}=await pool.query('UPDATE articles SET views=views+1 WHERE id=$1 AND published=true RETURNING views',[req.params.id]);if(!rows[0])return res.status(404).json({error:'Story not found.'});if(req.user?.sub)await pool.query('INSERT INTO reading_history(user_id,article_id) VALUES($1,$2) ON CONFLICT(user_id,article_id) DO UPDATE SET read_at=now()',[req.user.sub,req.params.id]);res.json({views:rows[0].views})}))
app.get('/api/articles/:id/comments',asyncRoute(async(req,res)=>{const {rows}=await pool.query(`SELECT c.id,c.body,c.created_at,u.display_name AS author FROM comments c JOIN users u ON u.id=c.user_id WHERE c.article_id=$1 ORDER BY c.created_at ASC LIMIT 100`,[req.params.id]);res.json({comments:rows})}))
app.post('/api/articles/:id/comments',authenticate,asyncRoute(async(req,res)=>{const {body}=z.object({body:z.string().trim().min(1).max(2000)}).parse(req.body);const {rows}=await pool.query('INSERT INTO comments(user_id,article_id,body) VALUES($1,$2,$3) RETURNING id,body,created_at',[req.user.sub,req.params.id,body]);const u=await pool.query('SELECT display_name FROM users WHERE id=$1',[req.user.sub]);res.status(201).json({comment:{...rows[0],author:u.rows[0].display_name}})}))
app.delete('/api/comments/:id',authenticate,asyncRoute(async(req,res)=>{const result=await pool.query('DELETE FROM comments WHERE id=$1 AND (user_id=$2 OR $3 IN (\'editor\',\'admin\'))',[req.params.id,req.user.sub,req.user.role]);if(!result.rowCount)return res.status(404).json({error:'Comment not found or cannot be removed.'});res.json({ok:true})}))
app.get(['/api/me/bookmarks','/api/bookmarks'],authenticate,asyncRoute(async(req,res)=>{const {rows}=await pool.query('SELECT a.* FROM bookmarks b JOIN articles a ON a.id=b.article_id WHERE b.user_id=$1 ORDER BY b.created_at DESC',[req.user.sub]);res.json({articles:rows.map(articleOut)})}))
app.get('/api/me/history',authenticate,asyncRoute(async(req,res)=>{const {rows}=await pool.query('SELECT a.* FROM reading_history h JOIN articles a ON a.id=h.article_id WHERE h.user_id=$1 ORDER BY h.read_at DESC LIMIT 100',[req.user.sub]);res.json({articles:rows.map(articleOut)})}))
app.post(['/api/me/bookmarks/:articleId','/api/bookmarks/:articleId'],authenticate,asyncRoute(async(req,res)=>{const {rowCount}=await pool.query('INSERT INTO bookmarks(user_id,article_id) SELECT $1,id FROM articles WHERE id=$2 AND published=true ON CONFLICT DO NOTHING',[req.user.sub,req.params.articleId]);if(!rowCount)return res.status(404).json({error:'Published story not found.'});res.status(201).json({ok:true})}))
app.delete(['/api/me/bookmarks/:articleId','/api/bookmarks/:articleId'],authenticate,asyncRoute(async(req,res)=>{await pool.query('DELETE FROM bookmarks WHERE user_id=$1 AND article_id=$2',[req.user.sub,req.params.articleId]);res.json({ok:true})}))
app.post('/api/articles/:id/like',authenticate,asyncRoute(async(req,res)=>{await pool.query('INSERT INTO likes(user_id,article_id) SELECT $1,id FROM articles WHERE id=$2 AND published=true ON CONFLICT DO NOTHING',[req.user.sub,req.params.id]);const {rows}=await pool.query('SELECT count(*)::int AS count FROM likes WHERE article_id=$1',[req.params.id]);res.json({liked:true,count:rows[0].count})}))
app.delete('/api/articles/:id/like',authenticate,asyncRoute(async(req,res)=>{await pool.query('DELETE FROM likes WHERE user_id=$1 AND article_id=$2',[req.user.sub,req.params.id]);const {rows}=await pool.query('SELECT count(*)::int AS count FROM likes WHERE article_id=$1',[req.params.id]);res.json({liked:false,count:rows[0].count})}))
app.get('/api/articles/:id/likes',optionalAuth,asyncRoute(async(req,res)=>{const {rows}=await pool.query('SELECT count(*)::int AS count,COALESCE(bool_or(user_id=$2),false) AS liked FROM likes WHERE article_id=$1',[req.params.id,req.user?.sub||null]);res.json({count:rows[0].count,liked:rows[0].liked})}))
app.post('/api/newsletter',asyncRoute(async(req,res)=>{const {email}=z.object({email:z.string().email().max(254)}).parse(req.body);await pool.query('INSERT INTO newsletter_subscribers(email) VALUES($1) ON CONFLICT(email) DO NOTHING',[email.trim().toLowerCase()]);res.status(201).json({ok:true,message:'You’re on the list. See you Sunday.'})}))

app.get('/api/admin/articles',authenticate,allowRoles('editor','admin'),asyncRoute(async(_req,res)=>{const {rows}=await pool.query('SELECT * FROM articles ORDER BY created_at DESC');res.json({articles:rows.map(articleOut)})}))
app.post('/api/admin/articles',authenticate,allowRoles('editor','admin'),asyncRoute(async(req,res)=>{const a=articleSchema.parse(req.body);const {rows}=await pool.query(`INSERT INTO articles(category,title,excerpt,author,role,author_bio,image,body,read_time,featured,published,source_name,source_url,source_published_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *`,[a.category,a.title,a.excerpt,a.author,a.role,a.authorBio,a.image,a.body,a.time,a.featured,a.published,a.sourceName,a.sourceUrl||'',a.sourceDate||null]);res.status(201).json({article:articleOut(rows[0])})}))
app.patch('/api/admin/articles/:id',authenticate,allowRoles('editor','admin'),asyncRoute(async(req,res)=>{const a=articleSchema.partial().parse(req.body);const cols={category:'category',title:'title',excerpt:'excerpt',author:'author',role:'role',authorBio:'author_bio',image:'image',body:'body',time:'read_time',featured:'featured',published:'published',sourceName:'source_name',sourceUrl:'source_url',sourceDate:'source_published_at'};const entries=Object.entries(a);if(!entries.length)return res.status(400).json({error:'No article fields supplied.'});const values=[req.params.id,...entries.map(([key,value])=>key==='sourceUrl'&&!value?'':value)],sets=entries.map(([k],i)=>`${cols[k]}=$${i+2}`);const {rows}=await pool.query(`UPDATE articles SET ${sets.join(',')},updated_at=now() WHERE id=$1 RETURNING *`,values);if(!rows[0])return res.status(404).json({error:'Story not found.'});res.json({article:articleOut(rows[0])})}))
app.delete('/api/admin/articles/:id',authenticate,allowRoles('editor','admin'),asyncRoute(async(req,res)=>{const {rowCount}=await pool.query('DELETE FROM articles WHERE id=$1',[req.params.id]);if(!rowCount)return res.status(404).json({error:'Story not found.'});res.json({ok:true})}))

if(process.env.NODE_ENV==='production')app.use(express.static(path.join(root,'dist'),{index:false,maxAge:'1h'}))
app.use('/api',(req,res)=>res.status(404).json({error:'API route not found.'}))
if(process.env.NODE_ENV==='production')app.get(/.*/,(_req,res)=>res.sendFile(path.join(root,'dist','index.html')))
app.use((err,_req,res,_next)=>{if(err instanceof z.ZodError)return res.status(400).json({error:'Please check the submitted fields.',details:err.issues.map(x=>({field:x.path.join('.'),message:x.message}))});if(err.code==='23505')return res.status(409).json({error:'An account with that email already exists.'});if(err.code==='23503'||err.code==='22P02')return res.status(404).json({error:'The requested record was not found.'});console.error('API error:',err.message);res.status(500).json({error:'Something went wrong. Please try again.'})})

await initializeDatabase()
app.listen(port,'0.0.0.0',()=>console.log(`TOPSTORIES.WORLD API listening on :${port}`))
process.on('SIGTERM',async()=>{await pool.end();process.exit(0)})
