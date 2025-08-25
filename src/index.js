import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import mongoose from 'mongoose'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

const app = express()

// ---- ENV ----
const PORT = process.env.PORT || 8080
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret'
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*'
const MONGODB_URI = process.env.MONGODB_URI // mongodb+srv://...

// ---- Middlewares ----
app.use(cors({ origin: CORS_ORIGIN, credentials: false }))
app.use(express.json())

// ---- DB & Modelo ----
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true }
}, { timestamps: true })

const User = mongoose.model('User', userSchema)

// ---- Helpers ----
function sign(user) {
  return jwt.sign({ sub: user._id.toString(), email: user.email }, JWT_SECRET, { expiresIn: '1h' })
}

function auth(req, res, next) {
  const h = req.headers.authorization || ''
  const token = h.startsWith('Bearer ') ? h.slice(7) : null
  if (!token) return res.status(401).json({ error: 'No token' })
  try {
    req.user = jwt.verify(token, JWT_SECRET)
    next()
  } catch {
    res.status(401).json({ error: 'Token inválido' })
  }
}

// ---- Rutas ----
app.get('/health', (_, res) => res.json({ ok: true }))

app.post('/auth/register', async (req, res) => {
  const { email, password } = req.body || {}
  if (!email || !password) return res.status(400).json({ error: 'Faltan campos' })
  const exists = await User.findOne({ email })
  if (exists) return res.status(409).json({ error: 'Email ya registrado' })
  const passwordHash = await bcrypt.hash(password, 10)
  const user = await User.create({ email, passwordHash })
  const token = sign(user)
  res.status(201).json({ token })
})

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {}
  if (!email || !password) return res.status(400).json({ error: 'Faltan campos' })
  const user = await User.findOne({ email })
  if (!user) return res.status(401).json({ error: 'Credenciales inválidas' })
  const ok = await bcrypt.compare(password, user.passwordHash)
  if (!ok) return res.status(401).json({ error: 'Credenciales inválidas' })
  const token = sign(user)
  res.json({ token })
})

app.get('/auth/me', auth, async (req, res) => {
  const user = await User.findById(req.user.sub).select('_id email createdAt')
  res.json(user)
})

// ---- Arranque ----
mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log('✅ Conectado a MongoDB')
    app.listen(PORT, '0.0.0.0', () => console.log(`Auth API en :${PORT}`))
  })
  .catch((e) => {
    console.error('❌ Error MongoDB:', e.message)
    process.exit(1)
  })
