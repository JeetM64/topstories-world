import pg from 'pg'
import bcrypt from 'bcryptjs'
import { newsSeeds } from './stories.js'
const { Pool } = pg
export const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 15, idleTimeoutMillis: 30000 })

const schema = `
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL, display_name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'reader' CHECK (role IN ('reader','editor','admin')),
  bio TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS articles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(), category TEXT NOT NULL, title TEXT NOT NULL,
  excerpt TEXT NOT NULL, author TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'Staff Writer', author_bio TEXT NOT NULL DEFAULT '',
  image TEXT NOT NULL DEFAULT '', body TEXT NOT NULL, read_time TEXT NOT NULL DEFAULT '5 min read',
  featured BOOLEAN NOT NULL DEFAULT false, published BOOLEAN NOT NULL DEFAULT false,
  views INTEGER NOT NULL DEFAULT 0, source_name TEXT NOT NULL DEFAULT '', source_url TEXT NOT NULL DEFAULT '',
  source_published_at DATE, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE articles ADD COLUMN IF NOT EXISTS source_name TEXT NOT NULL DEFAULT '';
ALTER TABLE articles ADD COLUMN IF NOT EXISTS source_url TEXT NOT NULL DEFAULT '';
ALTER TABLE articles ADD COLUMN IF NOT EXISTS source_published_at DATE;
ALTER TABLE articles ADD COLUMN IF NOT EXISTS author_bio TEXT NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS bookmarks (
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  article_id UUID NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY(user_id, article_id)
);
CREATE TABLE IF NOT EXISTS likes (
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  article_id UUID NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY(user_id, article_id)
);
CREATE TABLE IF NOT EXISTS comments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  article_id UUID NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
  body TEXT NOT NULL CHECK (char_length(body) BETWEEN 1 AND 2000), created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS reading_history (
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  article_id UUID NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
  read_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY(user_id, article_id)
);
CREATE TABLE IF NOT EXISTS newsletter_subscribers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email TEXT NOT NULL UNIQUE,
  subscribed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS articles_published_created_idx ON articles(published, created_at DESC);
CREATE INDEX IF NOT EXISTS comments_article_created_idx ON comments(article_id, created_at);
CREATE INDEX IF NOT EXISTS reading_history_user_read_idx ON reading_history(user_id, read_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS articles_source_url_unique_idx ON articles(source_url) WHERE source_url <> '';
`
export async function initializeDatabase() {
  await pool.query('CREATE EXTENSION IF NOT EXISTS pgcrypto')
  await pool.query(schema)
  await pool.query(`DELETE FROM articles WHERE title IN ('The intelligence we made — and the questions we haven’t answered','The grid that learns to dance with the sun','Markets find a new compass in an uncertain world') AND source_url=''`)
  for (const a of newsSeeds) await pool.query(`INSERT INTO articles
    (category,title,excerpt,author,role,author_bio,image,body,read_time,featured,published,source_name,source_url,source_published_at)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,true,$11,$12,$13)
    ON CONFLICT (source_url) WHERE source_url <> '' DO UPDATE SET category=excluded.category,title=excluded.title,excerpt=excluded.excerpt,author=excluded.author,role=excluded.role,author_bio=excluded.author_bio,image=excluded.image,body=excluded.body,read_time=excluded.read_time,featured=excluded.featured,published=true,source_name=excluded.source_name,source_published_at=excluded.source_published_at,updated_at=now()`,
    [a.category,a.title,a.excerpt,a.author,a.role,a.authorBio||`${a.role} covering the stories shaping our world.`,a.image,a.body,a.time,a.featured,a.sourceName,a.sourceUrl,a.sourceDate||null])
  await pool.query(`UPDATE articles SET featured=false WHERE title<>$1`,[newsSeeds.find(a=>a.featured).title])
  await pool.query(`UPDATE articles SET featured=true WHERE source_url=$1`,[newsSeeds.find(a=>a.featured).sourceUrl])
  const email=process.env.ADMIN_EMAIL?.trim().toLowerCase(),password=process.env.ADMIN_PASSWORD
  if (email&&password) await pool.query(`INSERT INTO users(email,password_hash,display_name,role) VALUES($1,$2,'Newsroom Editor','admin') ON CONFLICT(email) DO UPDATE SET role='admin'`,[email,await bcrypt.hash(password,12)])
}
