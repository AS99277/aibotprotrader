require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const qrcode = require('qrcode');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const nodemailer = require('nodemailer');
const TelegramBot = require('node-telegram-bot-api');

const app = express();
app.use(helmet({ contentSecurityPolicy: false })); // Disabled CSP for inline scripts in this unified architecture
app.use(cors());
app.use(express.json({ limit: '5mb' })); // Limit for Base64 proof uploads
app.use(express.urlencoded({ extended: true }));
app.use(mongoSanitize());

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, message: "Too many requests, try again later." });
app.use('/api/auth', limiter);

// --- NOTIFICATION SERVICES ---
let bot = null;
if (process.env.TELEGRAM_BOT_TOKEN) {
    bot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN, { polling: false });
}
const sendTelegramAdmin = async (message) => {
    if (bot && process.env.TELEGRAM_ADMIN_CHAT_ID) {
        try { await bot.sendMessage(process.env.TELEGRAM_ADMIN_CHAT_ID, message, { parse_mode: 'HTML' }); } 
        catch (err) { console.error('Telegram Error:', err.message); }
    }
};

const mailTransporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST, port: process.env.EMAIL_PORT, secure: process.env.EMAIL_PORT == 465,
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASSWORD }
});
const sendEmail = async (to, subject, html) => {
    if(!process.env.EMAIL_USER) return;
    try { await mailTransporter.sendMail({ from: process.env.EMAIL_FROM || process.env.EMAIL_USER, to, subject, html }); } 
    catch (err) { console.error('Email Error:', err.message); }
};

// --- DATABASE CONNECTION ---
let cachedDb = null;
async function connectDB() {
    if (cachedDb) return cachedDb;
    if (!process.env.MONGODB_URI) throw new Error('MONGODB_URI missing');
    cachedDb = await mongoose.connect(process.env.MONGODB_URI);
    return cachedDb;
}

// --- MONGOOSE SCHEMAS ---
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    phone: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    status: { type: String, enum: ['active', 'suspended'], default: 'active' },
    wallet: {
        available: { type: Number, default: 0 }, // stored in paise
        reserved: { type: Number, default: 0 },  // stored in paise
        totalDeposits: { type: Number, default: 0 },
        totalWithdrawals: { type: Number, default: 0 }
    }
}, { timestamps: true });

const planSchema = new mongoose.Schema({
    name: { type: String, required: true },
    amount: { type: Number, required: true }, // paise
    illustrativeDailyRate: { type: Number, required: true }, // percentage
    illustrativeDailyAmount: { type: Number, required: true }, // paise
    illustrativeThreshold: { type: Number, required: true }, // paise
    isActive: { type: Boolean, default: true }
});

const subscriptionSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    plan: { type: mongoose.Schema.Types.ObjectId, ref: 'Plan' },
    amount: { type: Number, required: true },
    status: { type: String, enum: ['pending', 'active', 'completed'], default: 'pending' },
}, { timestamps: true });

const paymentSchema = new mongoose.Schema({
    requestId: { type: String, required: true, unique: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    plan: { type: mongoose.Schema.Types.ObjectId, ref: 'Plan' },
    amount: { type: Number, required: true }, // paise
    utr: { type: String, required: true },
    proofData: { type: String }, // Base64 string restricted to < 5MB
    status: { type: String, enum: ['pending', 'verified', 'rejected'], default: 'pending' }
}, { timestamps: true });

const withdrawalSchema = new mongoose.Schema({
    requestId: { type: String, required: true, unique: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    amount: { type: Number, required: true }, // paise
    paymentMethod: { type: String, required: true },
    status: { type: String, enum: ['pending', 'under_review', 'approved', 'rejected', 'paid'], default: 'pending' },
    adminNote: { type: String }
}, { timestamps: true });

const ledgerSchema = new mongoose.Schema({
    transactionId: { type: String, required: true, unique: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    type: { type: String, enum: ['deposit', 'withdrawal', 'reward', 'admin_adjustment', 'withdrawal_refund'] },
    amount: { type: Number, required: true }, // paise
    debitOrCredit: { type: String, enum: ['credit', 'debit'] },
    reference: { type: String },
    description: { type: String }
}, { timestamps: true });

const taskSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    date: { type: String, required: true }, // YYYY-MM-DD
    completions: { type: Number, default: 0 }
}, { timestamps: true });

const notificationSchema = new mongoose.Schema({
    type: { type: String, required: true },
    message: { type: String, required: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    read: { type: Boolean, default: false }
}, { timestamps: true });

const auditSchema = new mongoose.Schema({
    admin: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    action: { type: String, required: true },
    target: { type: String },
    reason: { type: String },
    details: { type: Object }
}, { timestamps: true });

const User = mongoose.models.User || mongoose.model('User', userSchema);
const Plan = mongoose.models.Plan || mongoose.model('Plan', planSchema);
const Subscription = mongoose.models.Subscription || mongoose.model('Subscription', subscriptionSchema);
const Payment = mongoose.models.Payment || mongoose.model('Payment', paymentSchema);
const Withdrawal = mongoose.models.Withdrawal || mongoose.model('Withdrawal', withdrawalSchema);
const Ledger = mongoose.models.Ledger || mongoose.model('Ledger', ledgerSchema);
const TaskCompletion = mongoose.models.TaskCompletion || mongoose.model('TaskCompletion', taskSchema);
const AdminNotification = mongoose.models.Notification || mongoose.model('Notification', notificationSchema);
const AuditLog = mongoose.models.AuditLog || mongoose.model('AuditLog', auditSchema);

// --- DB INITIALIZATION ---
async function initDB() {
    await connectDB();
    if (await Plan.countDocuments() === 0) {
        await Plan.insertMany([
            { name: 'Starter', amount: 50000, illustrativeDailyRate: 2, illustrativeDailyAmount: 1000, illustrativeThreshold: 100000 },
            { name: 'Silver', amount: 100000, illustrativeDailyRate: 2, illustrativeDailyAmount: 2000, illustrativeThreshold: 200000 },
            { name: 'Gold', amount: 200000, illustrativeDailyRate: 2, illustrativeDailyAmount: 4000, illustrativeThreshold: 400000 },
            { name: 'Platinum', amount: 400000, illustrativeDailyRate: 2, illustrativeDailyAmount: 8000, illustrativeThreshold: 800000 },
            { name: 'Diamond', amount: 800000, illustrativeDailyRate: 2, illustrativeDailyAmount: 16000, illustrativeThreshold: 1600000 },
            { name: 'VIP', amount: 1500000, illustrativeDailyRate: 2, illustrativeDailyAmount: 30000, illustrativeThreshold: 3000000 }
        ]);
    }
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@platform.com';
    if (!(await User.findOne({ email: adminEmail })) && process.env.ADMIN_PASSWORD_HASH) {
        await User.create({ name: 'Super Admin', email: adminEmail, phone: '0000000000', password: process.env.ADMIN_PASSWORD_HASH, role: 'admin' });
    }
}
initDB().catch(console.error);

// --- MIDDLEWARE ---
const authMiddleware = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) throw new Error('Unauthorized');
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.id);
        if (!req.user || req.user.status === 'suspended') throw new Error('Account inactive');
        next();
    } catch (e) { res.status(401).json({ error: 'Unauthorized Access' }); }
};

// --- USER API ROUTES ---
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, phone, password } = req.body;
        if (await User.findOne({ $or: [{ email }, { phone }] })) return res.status(400).json({ error: 'User exists' });
        const hash = await argon2.hash(password);
        await User.create({ name, email, phone, password: hash });
        res.json({ message: 'Registration complete.' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || user.status === 'suspended' || !(await argon2.verify(user.password, password))) 
            return res.status(401).json({ error: 'Invalid credentials' });
        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.json({ token, role: user.role });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/user/dashboard', authMiddleware, async (req, res) => {
    const user = req.user;
    const activeSub = await Subscription.findOne({ user: user._id, status: 'active' }).populate('plan');
    const ledger = await Ledger.find({ user: user._id }).sort({ createdAt: -1 }).limit(10);
    const withdrawals = await Withdrawal.find({ user: user._id }).sort({ createdAt: -1 });
    res.json({ 
        user: { name: user.name, email: user.email, wallet: user.wallet }, 
        activeSub, ledger, withdrawals 
    });
});

app.get('/api/plans', async (req, res) => {
    const plans = await Plan.find({ isActive: true }).sort({ amount: 1 });
    res.json(plans);
});

app.post('/api/payment/request', authMiddleware, async (req, res) => {
    try {
        const plan = await Plan.findById(req.body.planId);
        if (!plan) return res.status(404).json({ error: 'Plan not found' });
        
        const upiId = process.env.UPI_ID || '6397319508@fam';
        const tn = `REQ${Date.now()}`;
        const amountINR = plan.amount / 100;
        const qrDataUrl = await qrcode.toDataURL(`upi://pay?pa=${upiId}&pn=Invest&am=${amountINR}&cu=INR&tn=${tn}`);

        res.json({ qrDataUrl, upiId, amountINR, planId: plan._id, planName: plan.name, tn });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/payment/verify', authMiddleware, async (req, res) => {
    try {
        const { planId, utr, proofData, tn } = req.body;
        const plan = await Plan.findById(planId);
        if (await Payment.findOne({ utr })) return res.status(400).json({ error: 'UTR already exists' });

        const payment = await Payment.create({ 
            requestId: tn, user: req.user._id, plan: planId, amount: plan.amount, utr, proofData 
        });

        const notifMsg = `<b>NEW DEPOSIT REQUEST</b>\nID: ${tn}\nUser: ${req.user.email}\nAmount: ₹${plan.amount/100}\nUTR: ${utr}`;
        await sendTelegramAdmin(notifMsg);
        await AdminNotification.create({ type: 'DEPOSIT', message: `Deposit request ₹${plan.amount/100} by ${req.user.email}`, user: req.user._id });
        await sendEmail(req.user.email, 'Payment Request Received', `<p>We received your payment proof for ₹${plan.amount/100}. Waiting for verification.</p>`);

        res.json({ message: 'Submitted for verification.' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/withdraw', authMiddleware, async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();
    try {
        const { amountINR, paymentMethod } = req.body;
        const amountPaise = parseInt(amountINR) * 100;
        const user = await User.findById(req.user._id).session(session);

        if (user.wallet.available < amountPaise) throw new Error('Insufficient eligible balance');
        
        // Reserve Funds
        user.wallet.available -= amountPaise;
        user.wallet.reserved += amountPaise;
        await user.save();

        const requestId = `WDR${Date.now()}`;
        await Withdrawal.create([{ requestId, user: user._id, amount: amountPaise, paymentMethod }], { session });
        await Ledger.create([{ transactionId: `L-${requestId}`, user: user._id, type: 'withdrawal', amount: amountPaise, debitOrCredit: 'debit', description: 'Withdrawal Reserved' }], { session });

        await session.commitTransaction();
        
        const notifMsg = `<b>NEW WITHDRAWAL</b>\nID: ${requestId}\nUser: ${user.email}\nAmount: ₹${amountINR}\nMethod: ${paymentMethod}`;
        await sendTelegramAdmin(notifMsg);
        await AdminNotification.create({ type: 'WITHDRAWAL', message: `Withdrawal ₹${amountINR} by ${user.email}`, user: user._id });

        res.json({ message: 'Withdrawal requested securely.' });
    } catch (e) { 
        await session.abortTransaction();
        res.status(400).json({ error: e.message }); 
    } finally { session.endSession(); }
});

app.post('/api/tasks/complete', authMiddleware, async (req, res) => {
    try {
        const today = new Date().toISOString().split('T')[0];
        let task = await TaskCompletion.findOne({ user: req.user._id, date: today });
        if (!task) task = await TaskCompletion.create({ user: req.user._id, date: today });
        
        if (task.completions >= 5) return res.status(400).json({ error: 'Daily limit reached.' });
        task.completions += 1;
        await task.save();

        if (task.completions === 5) {
            const sub = await Subscription.findOne({ user: req.user._id, status: 'active' }).populate('plan');
            if (sub) {
                const reward = sub.plan.illustrativeDailyAmount;
                await User.findByIdAndUpdate(req.user._id, { $inc: { 'wallet.available': reward } });
                await Ledger.create({ transactionId: `REW-${Date.now()}`, user: req.user._id, type: 'reward', amount: reward, debitOrCredit: 'credit', description: 'Daily Task Reward' });
                return res.json({ message: 'All tasks completed! Reward credited.', progress: 5, rewarded: true });
            }
        }
        res.json({ message: `Task ${task.completions}/5 completed.`, progress: task.completions, rewarded: false });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Admin Router Mount
app.use('/admin', require('./admin'));

// --- CLAYMORPHISM FRONTEND UI ---
app.get('/', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>InvestPro - Premium Returns</title>
    <style>
        :root {
            --bg-grad: linear-gradient(135deg, #e0c3fc 0%, #8ec5fc 100%);
            --clay-bg: rgba(255, 255, 255, 0.6);
            --clay-shadow: 10px 10px 20px rgba(142, 197, 252, 0.5), -10px -10px 20px rgba(255, 255, 255, 0.9);
            --clay-border: 2px solid rgba(255, 255, 255, 0.8);
            --primary: #5a67d8; --text: #2d3748;
        }
        @media (prefers-reduced-motion: reduce) { * { animation: none !important; transition: none !important; } }
        body { margin: 0; font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg-grad); color: var(--text); min-height: 100vh; display: flex; flex-direction: column; }
        nav { padding: 15px 5%; display: flex; justify-content: space-between; align-items: center; background: var(--clay-bg); backdrop-filter: blur(12px); box-shadow: var(--clay-shadow); margin-bottom: 20px; border-radius: 0 0 20px 20px; }
        nav h1 { margin: 0; font-size: 24px; color: var(--primary); font-weight: 800; }
        .nav-links a { margin-left: 20px; text-decoration: none; color: var(--text); font-weight: 600; cursor: pointer; }
        .container { flex: 1; max-width: 1200px; margin: 0 auto; padding: 20px; width: 100%; box-sizing: border-box; }
        
        .clay-card { background: var(--clay-bg); backdrop-filter: blur(12px); border-radius: 30px; box-shadow: var(--clay-shadow); border: var(--clay-border); padding: 30px; margin-bottom: 25px; transition: transform 0.3s ease; }
        .clay-card:hover { transform: translateY(-5px); }
        
        .btn { background: var(--primary); color: white; border: none; padding: 14px 28px; border-radius: 20px; cursor: pointer; font-size: 16px; font-weight: bold; box-shadow: 5px 5px 15px rgba(90, 103, 216, 0.4), -5px -5px 15px rgba(255,255,255,0.7); transition: all 0.2s; }
        .btn:active { box-shadow: inset 4px 4px 10px rgba(0,0,0,0.2), inset -4px -4px 10px rgba(255,255,255,0.5); }
        .btn-full { width: 100%; margin-top: 15px; }
        
        input, select { width: 100%; padding: 15px; margin: 10px 0; border-radius: 15px; border: none; background: rgba(255,255,255,0.9); box-shadow: inset 4px 4px 8px rgba(0,0,0,0.1), inset -4px -4px 8px rgba(255,255,255,0.8); outline: none; box-sizing: border-box; font-size: 15px; }
        
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 30px; }
        .text-center { text-align: center; }
        .disclaimer { font-size: 12px; background: rgba(255, 243, 205, 0.8); padding: 12px; border-radius: 12px; margin-top: 15px; color: #665c3e; font-weight: 500; }
        
        footer { padding: 30px; text-align: center; background: var(--clay-bg); backdrop-filter: blur(10px); box-shadow: 0 -5px 15px rgba(0,0,0,0.05); font-size: 14px; margin-top: auto; }
        .contact-pill { display: inline-block; padding: 8px 16px; background: rgba(255,255,255,0.8); border-radius: 20px; margin: 5px; box-shadow: 2px 2px 5px rgba(0,0,0,0.1); text-decoration: none; color: var(--primary); font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; } th, td { padding: 12px; text-align: left; border-bottom: 1px solid rgba(0,0,0,0.1); }
    </style>
</head>
<body>
    <nav>
        <h1>InvestPro</h1>
        <div class="nav-links" id="nav-links"></div>
    </nav>
    <div class="container" id="app"></div>
    
    <footer>
        <p>Support: +91 9927766450 | WhatsApp: +91 7060969508 | Email: anmolsingh99277@gmail.com</p>
        <p
