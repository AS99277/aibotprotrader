const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const router = express.Router();

// --- ADMIN MIDDLEWARE ---
const adminAuth = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) throw new Error('No Token');
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (decoded.role !== 'admin') throw new Error('Forbidden');
        req.adminId = decoded.id;
        next();
    } catch (e) { res.status(403).json({ error: 'Admin Access Denied' }); }
};

// --- ADMIN APIS ---
router.get('/api/stats', adminAuth, async (req, res) => {
    const data = {
        users: await mongoose.model('User').countDocuments({ role: 'user' }),
        pendingDeposits: await mongoose.model('Payment').find({ status: 'pending' }).populate('user plan'),
        pendingWithdrawals: await mongoose.model('Withdrawal').find({ status: 'pending' }).populate('user'),
        logs: await mongoose.model('AuditLog').find().sort({ createdAt: -1 }).limit(20).populate('admin', 'email')
    };
    res.json(data);
});

router.post('/api/wallet/adjust', adminAuth, async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();
    try {
        const { userEmail, amountINR, actionType, reason } = req.body; // actionType = 'credit' or 'debit'
        const amountPaise = parseInt(amountINR) * 100;
        if (!amountPaise || amountPaise <= 0) throw new Error('Invalid Amount');

        const User = mongoose.model('User');
        const targetUser = await User.findOne({ email: userEmail }).session(session);
        if (!targetUser) throw new Error('User not found');

        if (actionType === 'debit' && targetUser.wallet.available < amountPaise) {
            throw new Error('Insufficient available balance to debit');
        }

        const incVal = actionType === 'credit' ? amountPaise : -amountPaise;
        targetUser.wallet.available += incVal;
        await targetUser.save();

        const txId = `ADM-${Date.now()}`;
        await mongoose.model('Ledger').create([{ transactionId: txId, user: targetUser._id, type: 'admin_adjustment', amount: amountPaise, debitOrCredit: actionType, description: reason }], { session });
        await mongoose.model('AuditLog').create([{ admin: req.adminId, action: `Wallet ${actionType}`, target: targetUser.email, reason, details: { amountINR } }], { session });

        await session.commitTransaction();
        res.json({ message: `Successfully ${actionType}ed ₹${amountINR} for ${targetUser.email}` });
    } catch (e) {
        await session.abortTransaction();
        res.status(400).json({ error: e.message });
    } finally { session.endSession(); }
});

router.post('/api/deposit/verify/:id', adminAuth, async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();
    try {
        const { status, reason } = req.body; // 'verified' or 'rejected'
        const Payment = mongoose.model('Payment');
        const payment = await Payment.findById(req.params.id).populate('user plan').session(session);
        if (!payment || payment.status !== 'pending') throw new Error('Invalid or already processed payment');

        payment.status = status;
        await payment.save();

        if (status === 'verified') {
            await mongoose.model('Subscription').create([{ user: payment.user._id, plan: payment.plan._id, amount: payment.amount, status: 'active' }], { session });
            const user = await mongoose.model('User').findById(payment.user._id).session(session);
            user.wallet.totalDeposits += payment.amount;
            await user.save();
            await mongoose.model('Ledger').create([{ transactionId: `DEP-${payment.utr}`, user: user._id, type: 'deposit', amount: payment.amount, debitOrCredit: 'credit', reference: payment.utr }], { session });
        }

        await mongoose.model('AuditLog').create([{ admin: req.adminId, action: `Deposit ${status}`, target: payment.user.email, reason: reason || payment.utr }], { session });
        
        await session.commitTransaction();
        res.json({ message: `Payment marked as ${status}` });
    } catch (e) {
        await session.abortTransaction();
        res.status(400).json({ error: e.message });
    } finally { session.endSession(); }
});

router.post('/api/withdrawal/verify/:id', adminAuth, async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();
    try {
        const { status, reason } = req.body; // 'paid' or 'rejected'
        const Withdrawal = mongoose.model('Withdrawal');
        const wd = await Withdrawal.findById(req.params.id).populate('user').session(session);
        if (!wd || wd.status !== 'pending') throw new Error('Invalid or already processed withdrawal');

        wd.status = status;
        wd.adminNote = reason;
        await wd.save();

        const user = await mongoose.model('User').findById(wd.user._id).session(session);
        if (status === 'rejected') {
            // Release reserved funds back to available
            user.wallet.reserved -= wd.amount;
            user.wallet.available += wd.amount;
            await mongoose.model('Ledger').create([{ transactionId: `REF-${wd.requestId}`, user: user._id, type: 'withdrawal_refund', amount: wd.amount, debitOrCredit: 'credit', description: 'Withdrawal Rejected Refund' }], { session });
        } else if (status === 'paid') {
            // Funds permanently leave reserved pool
            user.wallet.reserved -= wd.amount;
            user.wallet.totalWithdrawals += wd.amount;
        }
        await user.save();

        await mongoose.model('AuditLog').create([{ admin: req.adminId, action: `Withdrawal ${status}`, target: wd.user.email, reason: reason || wd.requestId }], { session });
        
        await session.commitTransaction();
        res.json({ message: `Withdrawal marked as ${status}` });
    } catch (e) {
        await session.abortTransaction();
        res.status(400).json({ error: e.message });
    } finally { session.endSession(); }
});

// --- ADMIN FRONTEND UI ---
router.get('/', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Dashboard - InvestPro</title>
    <style>
        :root { --bg: #1a202c; --card: #2d3748; --text: #e2e8f0; --accent: #4fd1c5; }
        body { margin: 0; font-family: system-ui, sans-serif; background: var(--bg); color: var(--text); padding: 20px; }
        .container { max-width: 1200px; margin: auto; }
        .card { background: var(--card); padding: 20px; border-radius: 12px; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #4a5568; }
        button { background: var(--accent); color: #1a202c; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: bold; }
        .danger { background: #fc8181; }
        input, select { padding: 8px; border-radius: 4px; border: none; margin-right: 10px; }
    </style>
</head>
<body>
    <div class="container" id="app">Loading Secure Admin Panel...</div>
    <script>
        const API = '/admin/api';
        const paToInr = (paise) => (paise / 100).toFixed(2);

        async function req(ep, body = null) {
            const token = localStorage.getItem('token');
            if(!token) { window.location.href = '/#login'; return; }
            const opts = { headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token } };
            if (body) { opts.method = 'POST'; opts.body = JSON.stringify(body); }
            const res = await fetch(API + ep, opts);
            const data = await res.json();
            if (!res.ok) throw new Error(data.error);
            return data;
        }

        async function init() {
            try {
                const d = await req('/stats');
                
                let deps = d.pendingDeposits.map(p => \`<tr>
                    <td>\${p.user.email}</td><td>₹\${paToInr(p.amount)}</td><td>\${p.utr}</td>
                    <td><a href="\${p.proofData}" target="_blank" style="color:#4fd1c5">View Proof</a></td>
                    <td>
                        <button onclick="revDep('\${p._id}', 'verified')">Verify</button>
                        <button class="danger" onclick="revDep('\${p._id}', 'rejected')">Reject</button>
                    </td>
                </tr>\`).join('') || '<tr><td colspan="5">No pending deposits.</td></tr>';

                let wds = d.pendingWithdrawals.map(w => \`<tr>
                    <td>\${w.user.email}</td><td>₹\${paToInr(w.amount)}</td><td>\${w.paymentMethod}</td>
                    <td>
                        <button onclick="revWd('\${w._id}', 'paid')">Mark Paid</button>
                        <button class="danger" onclick="revWd('\${w._id}', 'rejected')">Reject</button>
                    </td>
                </tr>\`).join('') || '<tr><td colspan="4">No pending withdrawals.</td></tr>';
                
                let logs = d.logs.map(l => \`<tr><td>\${new Date(l.createdAt).toLocaleString()}</td><td>\${l.admin?.email}</td><td>\${l.action}</td><td>\${l.target}</td><td>\${l.reason}</td></tr>\`).join('');

                document.getElementById('app').innerHTML = \`
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 20px;">
                        <h2>InvestPro Admin Command Center</h2>
                        <div>Users: \${d.users} <button onclick="localStorage.removeItem('token'); window.location.href='/'" style="margin-left:15px">Logout</button></div>
                    </div>

                    <div class="card">
                        <h3>Wallet Adjustment (Atomic)</h3>
                        <form onsubmit="event.preventDefault(); adjWallet()">
                            <input type="email" id="a_email" placeholder="User Email" required>
                            <input type="number" id="a_amt" placeholder="Amount (INR)" required>
                            <select id="a_type"><option value="credit">Credit Balance</option><option value="debit">Debit Balance</option></select>
                            <input type="text" id="a_reason" placeholder="Audit Reason" required>
                            <button type="submit">Execute Adjustment</button>
                        </form>
                    </div>

                    <div class="card"><h3>Pending Deposits</h3><table><tr><th>User</th><th>Amount</th><th>UTR</th><th>Proof</th><th>Action</th></tr>\${deps}</table></div>
                    <div class="card"><h3>Pending Withdrawals</h3><table><tr><th>User</th><th>Amount</th><th>Method</th><th>Action</th></tr>\${wds}</table></div>
                    <div class="card"><h3>Recent Audit Logs</h3><table><tr><th>Date</th><th>Admin</th><th>Action</th><th>Target</th><th>Reason</th></tr>\${logs}</table></div>
                \`;
            } catch (e) { document.getElementById('app').innerHTML = \`<h2 style="color:red">Access Denied: \${e.message}</h2>\`; }
        }

        async function adjWallet() {
            if(!confirm(\`Confirm \${a_type.value.toUpperCase()} of ₹\${a_amt.value} for \${a_email.value}?\`)) return;
            try {
                const res = await req('/wallet/adjust', { userEmail: a_email.value, amountINR: a_amt.value, actionType: a_type.value, reason: a_reason.value });
                alert(res.message); init();
            } catch(e) { alert(e.message); }
        }

        async function revDep(id, status) {
            const reason = prompt(\`Enter reason for \${status} (Optional):\`);
            if(reason === null) return;
            try { await req('/deposit/verify/'+id, { status, reason }); init(); } catch(e) { alert(e.message); }
        }

        async function revWd(id, status) {
            const reason = prompt(\`Enter reference/reason for marking as \${status}:\`);
            if(reason === null) return;
            try { await req('/withdrawal/verify/'+id, { status, reason }); init(); } catch(e) { alert(e.message); }
        }

        window.onload = init;
    </script>
</body>
</html>
    `);
});

module.exports = router;
