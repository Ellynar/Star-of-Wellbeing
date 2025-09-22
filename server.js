import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import { RateLimiterMemory } from 'rate-limiter-flexible';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import puppeteer from 'puppeteer';
import { v4 as uuidv4 } from 'uuid'; // Import uuid
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

dotenv.config();
const app = express();
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(morgan('tiny'));

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// MongoDB Connection — switch between Railway env and local by commenting
// const MONGO = 'mongodb://localhost:27017/star_assessment'; // Local
const MONGO = process.env.MONGODB_URI || 'mongodb://localhost:27017/star_assessment'; // Online/Env
mongoose
  .connect(MONGO)
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error('MongoDB connection error:', err.message));

// User Schema
const UserSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  birthday: { type: Date, required: true },
  barangay: { type: String, required: true },
  cityMunicipality: { type: String },
  province: { type: String },
  region: { type: String },
  barangayCode: { type: String },
  cityCode: { type: String },
  provinceCode: { type: String },
  regionCode: { type: String },
  consentGiven: { type: Boolean, default: false },
  uid: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

// Assessment Schema
const AssessmentSchema = new mongoose.Schema({
  assessmentUid: { type: String, required: true, unique: true }, // Unique ID for the assessment
  user_parent_uid: { type: String, required: true, ref: 'User' }, // Link to User via uid
  assessmentData: { type: Object, required: true }, // Store the assessment choices
  sequenceNumber: { type: Number, default: 1 }, // 1,2,3... per user
  label: { type: String }, // e.g. "Assessment 1"
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Assessment = mongoose.model('Assessment', AssessmentSchema);

// Auth helpers
function signToken(payload) {
  const secret = process.env.JWT_SECRET || 'dev_secret_star_assessment';
  return jwt.sign(payload, secret, { expiresIn: '7d' });
}

function authMiddleware(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    const secret = process.env.JWT_SECRET || 'dev_secret_star_assessment';
    const decoded = jwt.verify(token, secret);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function calculateAgeInYears(birthdayInput) {
  const date = new Date(birthdayInput);
  if (isNaN(date.getTime())) return NaN;
  const now = new Date();
  let years = now.getFullYear() - date.getFullYear();
  const m = now.getMonth() - date.getMonth();
  if (m < 0 || (m === 0 && now.getDate() < date.getDate())) {
    years--;
  }
  return years;
}

// Auth routes
app.post('/auth/register', async (req, res) => {
  try {
    const { fullName, email, password, password2, birthday, barangay, cityMunicipality, province, region, barangayCode, cityCode, provinceCode, regionCode, consentGiven } = req.body;
    if (!fullName || !email || !password || !birthday || !barangay) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    if (password2 !== undefined && password !== password2) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }
    const years = calculateAgeInYears(birthday);
    if (!isFinite(years)) {
      return res.status(400).json({ error: 'Invalid birthday' });
    }
    if (years < 10) {
      return res.status(400).json({ error: 'Minimum age is 10' });
    }
    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ error: 'Email already registered' });
    const uid = uuidv4();
    const passwordHash = await bcrypt.hash(String(password), 10);
    const user = await User.create({
      fullName,
      email,
      birthday: new Date(birthday),
      barangay,
      cityMunicipality: cityMunicipality || '',
      province: province || '',
      region: region || '',
      barangayCode: barangayCode || '',
      cityCode: cityCode || '',
      provinceCode: provinceCode || '',
      regionCode: regionCode || '',
      consentGiven: !!consentGiven,
      uid,
      passwordHash
    });
    const token = signToken({ uid: user.uid, email: user.email, id: user._id });
    return res.status(201).json({ ok: true, token, uid: user.uid });
  } catch (e) {
    return res.status(500).json({ error: 'Registration failed', details: e.message });
  }
});

// PSGC proxy: provinces (for top-level select)
app.get('/psgc/provinces', async (req, res) => {
  try {
    const q = String(req.query.q || '').trim();
    const urls = [
      `https://psgc-api.wareneutron.com/api/provinces?${q ? `name=${encodeURIComponent(q)}&` : ''}per_page=200`,
      `https://psgc.cloud/api/provinces?${q ? `q=${encodeURIComponent(q)}&` : ''}per_page=200`
    ];
    async function fetchAll(url) {
      try {
        const r = await fetch(url);
        if (!r.ok) return [];
        const j = await r.json();
        const arr = Array.isArray(j?.data) ? j.data : (Array.isArray(j) ? j : []);
        return arr.map(it => ({
          name: it?.name || it?.province_name || '',
          code: it?.code || it?.psgc_code || it?.province_code || '',
          region: it?.region_name || it?.region || '',
          regionCode: it?.region_code || it?.regionCode || ''
        }));
      } catch { return []; }
    }
    const merged = (await Promise.all(urls.map(fetchAll))).flat();
    const seen = new Set();
    const dedup = merged.filter(x => { const k = `${x.name}|${x.region}`.toLowerCase(); if (seen.has(k)) return false; seen.add(k); return !!x.name; });
    const ql = q.toLowerCase();
    const ranked = dedup.sort((a,b) => {
      const ap = (a.name||'').toLowerCase().startsWith(ql) ? 0 : 1;
      const bp = (b.name||'').toLowerCase().startsWith(ql) ? 0 : 1;
      if (ap !== bp) return ap - bp; return (a.name||'').localeCompare(b.name||'');
    }).slice(0, 100);
    return res.json({ ok: true, suggestions: ranked });
  } catch (e) {
    console.error('PSGC provinces proxy error:', e);
    return res.status(500).json({ error: 'Failed to fetch provinces' });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Missing credentials' });
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(String(password), user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = signToken({ uid: user.uid, email: user.email, id: user._id });
    return res.json({ ok: true, token, uid: user.uid });
  } catch (e) {
    return res.status(500).json({ error: 'Login failed', details: e.message });
  }
});

// Current user
app.get('/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findOne({ uid: req.user.uid }).lean();
    if (!user) return res.status(404).json({ error: 'User not found' });
    const { passwordHash, __v, ...safe } = user;
    return res.json({ ok: true, user: safe });
  } catch (e) {
    return res.status(500).json({ error: 'Failed to load profile' });
  }
});

// Rate limiter
const limiter = new RateLimiterMemory({ points: 100, duration: 60 }); // 100 requests per minute
app.use(async (req, res, next) => {
  try { await limiter.consume(req.ip); next(); }
  catch { return res.status(429).json({ error: 'Too many requests' }); }
});

// Submission endpoint (protected)
app.post('/submit', authMiddleware, async (req, res) => {
  try {
    const { 
      fullName, 
      email, 
      birthday, 
      barangay, 
      cityMunicipality,
      province,
      region,
      barangayCode,
      cityCode,
      provinceCode,
      regionCode,
      consentGiven,
      data // Assessment choices
    } = req.body;

    // Validate required fields
    if (!fullName || !email || !birthday || !barangay || !data) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    const years = calculateAgeInYears(birthday);
    if (!isFinite(years)) {
      return res.status(400).json({ error: 'Invalid birthday' });
    }
    if (years < 10) {
      return res.status(400).json({ error: 'Minimum age is 10' });
    }

    // Use auth user uid for link; still allow update of basics
    const userUid = req.user?.uid || uuidv4();
    const assessmentUid = uuidv4(); // Generate unique UID for the assessment

    // Ensure user exists or update basics
    let user = await User.findOne({ uid: userUid });
    if (!user) {
      user = new User({
        fullName,
        email,
        birthday: new Date(birthday),
        barangay,
        cityMunicipality: cityMunicipality || '',
        province: province || '',
        region: region || '',
        barangayCode: barangayCode || '',
        cityCode: cityCode || '',
        provinceCode: provinceCode || '',
        regionCode: regionCode || '',
        consentGiven: !!consentGiven,
        uid: userUid,
        passwordHash: (await bcrypt.hash(uuidv4(), 10)) // placeholder if somehow missing
      });
    } else {
      user.fullName = fullName;
      user.email = email;
      user.birthday = new Date(birthday);
      user.barangay = barangay;
      user.cityMunicipality = cityMunicipality || '';
      user.province = province || '';
      user.region = region || '';
      user.barangayCode = barangayCode || '';
      user.cityCode = cityCode || '';
      user.provinceCode = provinceCode || '';
      user.regionCode = regionCode || '';
      user.consentGiven = !!consentGiven;
    }

    // Determine next sequence for this user
    const lastAssessment = await Assessment.findOne({ user_parent_uid: userUid }).sort({ sequenceNumber: -1 }).lean();
    const nextSeq = (lastAssessment?.sequenceNumber || 0) + 1;

    // Create new assessment with sequence
    const newAssessment = new Assessment({
      assessmentUid,
      user_parent_uid: userUid,
      assessmentData: data,
      sequenceNumber: nextSeq,
      label: `Assessment ${nextSeq}`
    });

    // Save to database
    const savedUser = await user.save();
    const savedAssessment = await newAssessment.save();

    return res.status(201).json({ 
      ok: true, 
      message: 'User and assessment data saved successfully', 
      userId: savedUser._id,
      assessmentId: savedAssessment._id,
      uid: savedUser.uid, // Return uid
      assessmentUid: savedAssessment.assessmentUid, // Return assessmentUid
      sequenceNumber: savedAssessment.sequenceNumber,
      label: savedAssessment.label
    });
  } catch (error) {
    console.error('Submission error:', error);
    return res.status(500).json({ error: 'Submission failed', details: error.message });
  }
});

// List assessments by user uid (protected)
app.get('/users/:uid/assessments', authMiddleware, async (req, res) => {
  try {
    const { uid } = req.params;
    const list = await Assessment.find({ user_parent_uid: uid }).sort({ createdAt: -1 }).lean();
    return res.json({ ok: true, count: list.length, assessments: list });
  } catch (e) {
    return res.status(500).json({ error: 'Failed to load assessments' });
  }
});

app.get('/users', async (req, res) => {
  try {
    const users = await User.find({});
    return res.status(200).json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    return res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.get('/assessments', async (req, res) => {
  try {
    const assessments = await Assessment.find({});
    return res.status(200).json(assessments);
  } catch (error) {
    console.error('Error fetching assessments:', error);
    return res.status(500).json({ error: 'Failed to fetch assessments' });
  }
});

// PSGC proxy for barangay suggestions
app.get('/psgc/barangays', async (req, res) => {
  try {
    const q = String(req.query.q || '').trim();
    const cityCodeFilter = String(req.query.cityCode || '').trim();
    const provinceCodeFilter = String(req.query.provinceCode || '').trim();
    // Allow: q-only, city-only, province-only
    if (!q && !cityCodeFilter && !provinceCodeFilter) return res.json({ ok: true, suggestions: [] });

    const norm = (s) => String(s || '')
      .toLowerCase()
      .normalize('NFD').replace(/\p{Diacritic}/gu, '')
      .replace(/[^a-z0-9\s]/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();

    const qNorm = norm(q);

    async function fetchProvider(url) {
      try {
        const r = await fetch(url);
        if (!r.ok) return [];
        const j = await r.json();
        const arr = Array.isArray(j?.data) ? j.data : Array.isArray(j?.value) ? j.value : (Array.isArray(j) ? j : []);
        return arr.map(it => ({
          name: it?.name || it?.brgy_name || '',
          code: it?.code || it?.psgc_code || it?.brgy_code || '',
          cityMunicipality: it?.city_municipality_name || it?.cityMunicipality || it?.city_name || it?.municipality_name || '',
          city_code: it?.city_code || it?.cityMunicipalityCode || it?.city_municipality_code || '',
          province: it?.province_name || it?.province || '',
          province_code: it?.province_code || it?.provinceCode || '',
          region: it?.region_name || it?.region || ''
        }));
      } catch { return []; }
    }

    let providers = [];
    if (cityCodeFilter) {
      // Fetch barangays for a specific city only (most accurate)
      const city = encodeURIComponent(String(cityCodeFilter).replace(/\D/g,''));
      providers = [
        `https://psgc-api.wareneutron.com/api/cities-municipalities/${city}/barangays?per_page=2000`,
        `https://psgc.cloud/api/cities-municipalities/${city}/barangays?per_page=2000`
      ];
    } else if (provinceCodeFilter) {
      // Province-wide barangays (can be large)
      const prov = encodeURIComponent(String(provinceCodeFilter).replace(/\D/g,''));
      providers = [
        `https://psgc-api.wareneutron.com/api/provinces/${prov}/barangays?per_page=4000`,
        `https://psgc.cloud/api/provinces/${prov}/barangays?per_page=4000`
      ];
    } else if (q) {
      // Fallback global search
      providers = [
        `https://psgc-api.wareneutron.com/api/barangays?name=${encodeURIComponent(q)}&per_page=1000`,
        `https://psgc.cloud/api/barangays?q=${encodeURIComponent(q)}&per_page=1000`
      ];
    }

    const resultsArrays = await Promise.all(providers.map(fetchProvider));
    let merged = ([]).concat(...resultsArrays);

    // When using nested endpoints, filtering is not required; keep merged as-is

    // Dedupe and optionally rank by query
    const seen = new Set();
    let deduped = merged.filter(it => {
      const key = `${it.name}|${it.cityMunicipality}|${it.province}`.toLowerCase();
      if (seen.has(key)) return false; seen.add(key); return !!it.name;
    });

    deduped = deduped.sort((a,b) => (a.name||'').localeCompare(b.name||''));

    if (q) {
      function isPrefix(t, qn){ return t.startsWith(qn); }
      function isSubstring(t, qn){ return t.includes(qn); }
      const ranked = deduped
        .map(it => { const t = norm(it.name); const s = isPrefix(t,qNorm)?0:isSubstring(t,qNorm)?1:2; return {it,s}; })
        .sort((a,b)=> a.s - b.s || a.it.name.localeCompare(b.it.name))
        .slice(0, 1000)
        .map(x=>x.it);
      return res.json({ ok: true, suggestions: ranked });
    }

    return res.json({ ok: true, suggestions: deduped.slice(0,4000) });
  } catch (e) {
    console.error('PSGC proxy error:', e);
    return res.status(500).json({ error: 'Failed to fetch barangay suggestions' });
  }
});

app.get('/generate-pdf', async (req, res) => {
  try {
    const { name = 'Anonymous', data = '{}' } = req.query;
    const reportPath = path.resolve(__dirname, '../assets/pdf-template/report.html');
    const reportUrl = `file://${reportPath}?name=${encodeURIComponent(name)}&data=${encodeURIComponent(data)}`;
    const browser = await puppeteer.launch({ headless: 'new', args: ['--no-sandbox','--disable-setuid-sandbox'] });
    const page = await browser.newPage();
    await page.goto(reportUrl, { waitUntil: 'networkidle0' });
    const pdfBuffer = await page.pdf({ format: 'A4', printBackground: true });
    await browser.close();
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'inline; filename="star-report.pdf"');
    return res.send(pdfBuffer);
  } catch (e) {
    return res.status(500).json({ error: 'PDF generation failed' });
  }
});

// PSGC proxy: cities/municipalities search
app.get('/psgc/cities', async (req, res) => {
  try {
    const q = String(req.query.q || '').trim();
    const provinceCodeFilter = String(req.query.provinceCode || '').trim();
    if (!q && !provinceCodeFilter) return res.json({ ok: true, suggestions: [] });
    const urls = [
      `https://psgc-api.wareneutron.com/api/cities-municipalities?${q ? `name=${encodeURIComponent(q)}&` : ''}per_page=500`,
      `https://psgc.cloud/api/cities-municipalities?${q ? `q=${encodeURIComponent(q)}&` : ''}per_page=500`
    ];
    // Provider-specific endpoints when provinceCode is known
    if (provinceCodeFilter) {
      const raw = String(provinceCodeFilter || '').replace(/\D/g, '');
      const trimmed = raw.replace(/0+$/,'');
      const short4 = trimmed.slice(0, 4);
      const candidates = Array.from(new Set([raw, trimmed, short4].filter(Boolean)));
      const pc = encodeURIComponent(raw);
      urls.push(
        `https://psgc-api.wareneutron.com/api/provinces/${pc}/cities-municipalities?per_page=500`,
        `https://psgc.cloud/api/provinces/${pc}/cities-municipalities?per_page=500`
      );
      // Also try with trimmed/short candidates
      for (const c of candidates) {
        const enc = encodeURIComponent(c);
        urls.push(
          `https://psgc-api.wareneutron.com/api/provinces/${enc}/cities-municipalities?per_page=500`,
          `https://psgc.cloud/api/provinces/${enc}/cities-municipalities?per_page=500`
        );
      }
    }
    async function fetchAll(url) {
      try {
        const r = await fetch(url);
        if (!r.ok) return [];
        const j = await r.json();
        // Normalize both provider shapes { data: [...] } and { value: [...] }
        const arr = Array.isArray(j?.data) ? j.data : Array.isArray(j?.value) ? j.value : (Array.isArray(j) ? j : []);
        return arr.map(it => ({
          name: it?.name || it?.city_name || it?.municipality_name || '',
          code: it?.code || it?.psgc_code || it?.city_code || it?.municipality_code || '',
          province: it?.province_name || it?.province || '',
          provinceCode: it?.province_code || it?.provinceCode || it?.prov_code || it?.provCode || '',
          region: it?.region_name || it?.region || '',
          regionCode: it?.region_code || it?.regionCode || ''
        }));
      } catch { return []; }
    }
    let results = (await Promise.all(urls.map(fetchAll))).flat();
    if (provinceCodeFilter) {
      const onlyDigits = (v) => String(v || '').replace(/\D/g, '');
      const trimTailZeros = (v) => onlyDigits(v).replace(/0+$/, '');
      const provRaw = onlyDigits(provinceCodeFilter);
      const provTrim = trimTailZeros(provRaw);
      const provPrefix4 = provTrim.slice(0, 4);

      // If provider didn't include province codes, fall back to prefix match on city code
      results = results.filter(x => {
        const cityCodeRaw = onlyDigits(x.code);
        const cityTrim = trimTailZeros(cityCodeRaw);
        const cityPrefix4 = cityTrim.slice(0, 4);
        const candProv = trimTailZeros(x.provinceCode || x.province_code);
        return (
          (candProv && (candProv === provTrim || candProv.slice(0,4) === provPrefix4)) ||
          (!candProv && cityPrefix4 === provPrefix4)
        );
      });
    }
    const seen = new Set();
    const dedup = results.filter(x => {
      const key = `${x.name}|${x.province}`.toLowerCase();
      if (seen.has(key)) return false; seen.add(key); return !!x.name;
    });
    const ql = q.toLowerCase();
    // If filtering by province without a text query, return full sorted list (for dropdown)
    if (provinceCodeFilter && !q) {
      const full = dedup.sort((a,b) => (a.name||'').localeCompare(b.name||''));
      return res.json({ ok: true, suggestions: full });
    }
    const ranked = dedup
      .map(it => ({ it, p: (it.name||'').toLowerCase().startsWith(ql) ? 0 : 1 }))
      .sort((a,b) => a.p - b.p || a.it.name.localeCompare(b.it.name))
      .slice(0, 8)
      .map(x => x.it);
    return res.json({ ok: true, suggestions: ranked });
  } catch (e) {
    console.error('PSGC cities proxy error:', e);
    return res.status(500).json({ error: 'Failed to fetch city suggestions' });
  }
});

// Port — prefers env PORT. If in use locally, gracefully try the next ports
const BASE_PORT = parseInt(process.env.PORT || '8080', 10);

function startServer(port, attempt = 0) {
  const server = app.listen(port, () => {
    const actualPort = server.address().port;
    console.log(`Backend running on http://localhost:${actualPort}`);
  });

  server.on('error', (err) => {
    if (err && err.code === 'EADDRINUSE' && !process.env.PORT && attempt < 10) {
      const nextPort = port + 1;
      console.warn(`Port ${port} in use, trying ${nextPort}...`);
      startServer(nextPort, attempt + 1);
    } else {
      console.error('Failed to start server:', err);
      process.exit(1);
    }
  });
}

startServer(BASE_PORT);


