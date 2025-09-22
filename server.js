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
mongoose.connect(MONGO, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// User Schema
const UserSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  age: { type: Number, required: true },
  address: { type: String, required: true },
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

// Auth routes
app.post('/auth/register', async (req, res) => {
  try {
    const { fullName, email, password, password2, age, address, consentGiven } = req.body;
    if (!fullName || !email || !password || !age || !address) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    if (password2 !== undefined && password !== password2) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }
    if (Number(age) < 10) {
      return res.status(400).json({ error: 'Minimum age is 10' });
    }
    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ error: 'Email already registered' });
    const uid = uuidv4();
    const passwordHash = await bcrypt.hash(String(password), 10);
    const user = await User.create({
      fullName,
      email,
      age,
      address,
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
      age, 
      address, 
      consentGiven,
      data // Assessment choices
    } = req.body;

    // Validate required fields
    if (!fullName || !email || !age || !address || !data) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    if (Number(age) < 10) {
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
        age,
        address,
        consentGiven: !!consentGiven,
        uid: userUid,
        passwordHash: (await bcrypt.hash(uuidv4(), 10)) // placeholder if somehow missing
      });
    } else {
      user.fullName = fullName;
      user.email = email;
      user.age = age;
      user.address = address;
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

// Port — Railway provides PORT, comment/uncomment for local override if needed
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Backend running on http://localhost:${PORT}`));


