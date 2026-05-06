const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const crypto = require('crypto');
const axios = require('axios');
require('dotenv').config();

// Initialize Firebase Admin (Requires process.env.GOOGLE_APPLICATION_CREDENTIALS or Firebase runtime)
admin.initializeApp();
const db = admin.firestore();

const app = express();

// Middleware to capture raw body for Cashfree Webhook Signature Verification
app.use(express.json({
    verify: (req, res, buf) => {
        req.rawBody = buf;
    }
}));
app.use(cors());

// Middleware: Authenticate Firebase User
const authenticate = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized: Missing or invalid token' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decodedToken = await admin.auth().verifyIdToken(token);
        req.user = decodedToken;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Unauthorized: Invalid token' });
    }
};

// Util: Generate Referral Code
const generateReferralCode = () => crypto.randomBytes(4).toString('hex').toUpperCase();

// ==========================================
// 1. AUTHENTICATION & USER SETUP
// ==========================================
app.post('/auth/signup', authenticate, async (req, res) => {
    try {
        const { username, email, referralCode } = req.body;
        const uid = req.user.uid;
        const userRef = db.collection('users').doc(uid);
        
        await db.runTransaction(async (t) => {
            const userDoc = await t.get(userRef);
            if (!userDoc.exists) {
                t.set(userRef, {
                    username: username || '',
                    email: email || req.user.email || '',
                    wallet: 0,
                    totalXP: 0,
                    joinedMatches: [],
                    referralCode: generateReferralCode(),
                    referredBy: referralCode || null,
                    matchesPlayed: 0,
                    totalKills: 0,
                    dailyStreak: 0,
                    lastDailyReward: 0,
                    isVIP: false,
                    createdAt: admin.firestore.FieldValue.serverTimestamp()
                });
            }
        });

        res.status(200).json({ success: true, message: 'User signed up successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==========================================
// 2. PAYMENT GATEWAY: CASHFREE
// ==========================================
app.post('/wallet/createOrder', authenticate, async (req, res) => {
    try {
        const { amount } = req.body;
        if (!amount || amount <= 0) return res.status(400).json({ error: 'Invalid amount' });

        const orderId = `ORDER_${Date.now()}_${req.user.uid}`;

        // Create Cashfree Order
        const response = await axios.post('https://sandbox.cashfree.com/pg/orders', {
            order_amount: amount,
            order_currency: "INR",
            order_id: orderId,
            customer_details: {
                customer_id: req.user.uid,
                customer_phone: "9999999999" // Can be mapped to actual user data
            }
        }, {
            headers: {
                'x-client-id': process.env.CASHFREE_APP_ID,
                'x-client-secret': process.env.CASHFREE_SECRET_KEY,
                'x-api-version': '2022-09-01',
                'Content-Type': 'application/json'
            }
        });

        // Store PENDING transaction
        await db.collection('transactions').doc(orderId).set({
            userId: req.user.uid,
            type: 'DEPOSIT',
            amount: amount,
            status: 'PENDING',
            orderId: orderId,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });

        res.json({ success: true, payment_session_id: response.data.payment_session_id, orderId });
    } catch (error) {
        res.status(500).json({ error: error.response?.data?.message || error.message });
    }
});

// Webhook: The ONLY place wallet gets credited for deposits
app.post('/webhook/cashfree', async (req, res) => {
    try {
        const signature = req.headers['x-webhook-signature'];
        const timestamp = req.headers['x-webhook-timestamp'];
        const rawBody = req.rawBody.toString();

        const secretKey = process.env.CASHFREE_SECRET_KEY;
        const expectedSignature = crypto.createHmac('sha256', secretKey)
            .update(timestamp + rawBody)
            .digest('base64');

        if (signature !== expectedSignature) {
            return res.status(400).json({ error: 'Invalid webhook signature' });
        }

        const { data, type } = req.body;
        if (type !== 'PAYMENT_SUCCESS_WEBHOOK') {
            return res.status(200).send('Ignored');
        }

        const orderId = data.order.order_id;
        const paymentAmount = data.payment.payment_amount;

        // Transactional Wallet Update (Idempotent)
        await db.runTransaction(async (t) => {
            const txRef = db.collection('transactions').doc(orderId);
            const txDoc = await t.get(txRef);

            if (!txDoc.exists || txDoc.data().status !== 'PENDING') return;

            const userId = txDoc.data().userId;
            const userRef = db.collection('users').doc(userId);

            t.update(txRef, { status: 'SUCCESS' });
            t.update(userRef, {
                wallet: admin.firestore.FieldValue.increment(paymentAmount)
            });
        });

        res.status(200).send('OK');
    } catch (error) {
        res.status(500).send('Webhook Processing Error');
    }
});

// ==========================================
// 3. MATCH JOINING
// ==========================================
app.post('/match/join', authenticate, async (req, res) => {
    try {
        const { matchId, gameUids } = req.body;
        const uid = req.user.uid;

        if (!matchId || !Array.isArray(gameUids) || gameUids.length === 0) {
            return res.status(400).json({ error: 'Invalid join data' });
        }

        await db.runTransaction(async (t) => {
            const matchRef = db.collection('matches').doc(matchId);
            const userRef = db.collection('users').doc(uid);
            const teamRef = matchRef.collection('teams').doc(uid);

            const [matchDoc, userDoc, teamDoc] = await Promise.all([
                t.get(matchRef), t.get(userRef), t.get(teamRef)
            ]);

            if (!matchDoc.exists) throw new Error('Match not found');
            if (!userDoc.exists) throw new Error('User not found');
            if (teamDoc.exists) throw new Error('You have already joined this match');

            const match = matchDoc.data();
            const user = userDoc.data();

            if (match.status !== 'upcoming' && match.status !== 'Upcoming') {
                throw new Error('Match is not accepting entries');
            }

            if ((match.joinedCount || 0) >= match.maxPlayers) {
                throw new Error('Match is fully booked');
            }

            if (user.wallet < match.entryFee) {
                throw new Error('Insufficient wallet balance');
            }

            const registeredUids = match.registeredGameUids || [];
            const hasDuplicate = gameUids.some(gUid => registeredUids.includes(gUid));
            if (hasDuplicate) throw new Error('One or more Game UIDs are already registered in this match');

            // Deduct Wallet & Update Match Data
            t.update(userRef, {
                wallet: admin.firestore.FieldValue.increment(-match.entryFee),
                joinedMatches: admin.firestore.FieldValue.arrayUnion(matchId)
            });

            t.update(matchRef, {
                joinedCount: admin.firestore.FieldValue.increment(1),
                registeredGameUids: admin.firestore.FieldValue.arrayUnion(...gameUids)
            });

            t.set(teamRef, {
                ownerUid: uid,
                ownerUsername: user.username,
                gameUids: gameUids,
                prizeDistributed: false,
                createdAt: admin.firestore.FieldValue.serverTimestamp()
            });

            const txRef = db.collection('transactions').doc();
            t.set(txRef, {
                userId: uid,
                type: 'MATCH_FEE',
                amount: -match.entryFee,
                matchId: matchId,
                status: 'SUCCESS',
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            });
        });

        res.json({ success: true, message: 'Joined match successfully' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// ==========================================
// 4. DAILY REWARDS
// ==========================================
app.post('/rewards/daily', authenticate, async (req, res) => {
    try {
        const uid = req.user.uid;
        
        await db.runTransaction(async (t) => {
            const userRef = db.collection('users').doc(uid);
            const userDoc = await t.get(userRef);
            
            if (!userDoc.exists) throw new Error('User not found');
            
            const userData = userDoc.data();
            const now = Date.now();
            const lastReward = userData.lastDailyReward || 0;
            const cooldown = 24 * 60 * 60 * 1000;

            if (now - lastReward < cooldown) {
                throw new Error('Daily reward already claimed today.');
            }

            const rewardAmount = 5; // Hardcoded daily reward amount
            let newStreak = (userData.dailyStreak || 0) + 1;
            
            // Reset streak if missed more than 48 hours
            if (now - lastReward > cooldown * 2 && lastReward !== 0) {
                newStreak = 1;
            }

            t.update(userRef, {
                wallet: admin.firestore.FieldValue.increment(rewardAmount),
                lastDailyReward: now,
                dailyStreak: newStreak
            });

            const txRef = db.collection('transactions').doc();
            t.set(txRef, {
                userId: uid,
                type: 'DAILY_REWARD',
                amount: rewardAmount,
                status: 'SUCCESS',
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            });
        });

        res.json({ success: true, message: 'Daily reward credited' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// ==========================================
// 5. WITHDRAWAL SYSTEM
// ==========================================
app.post('/wallet/withdraw', authenticate, async (req, res) => {
    try {
        const { amount, upiId } = req.body;
        const uid = req.user.uid;

        if (!amount || amount <= 0 || !upiId) {
            return res.status(400).json({ error: 'Invalid amount or UPI ID' });
        }

        await db.runTransaction(async (t) => {
            const userRef = db.collection('users').doc(uid);
            const userDoc = await t.get(userRef);
            
            if (!userDoc.exists) throw new Error('User not found');
            
            const walletBalance = userDoc.data().wallet || 0;
            if (walletBalance < amount) throw new Error('Insufficient wallet balance');

            // Immediately lock funds
            t.update(userRef, {
                wallet: admin.firestore.FieldValue.increment(-amount)
            });

            const txRef = db.collection('transactions').doc();
            t.set(txRef, {
                userId: uid,
                type: 'WITHDRAW',
                amount: amount,
                upiId: upiId,
                status: 'PENDING', // Awaiting Admin Approval
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            });
        });

        res.json({ success: true, message: 'Withdrawal requested successfully' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// ==========================================
// 6. ADMIN: DISTRIBUTE PRIZE
// ==========================================
app.post('/admin/match/distribute', authenticate, async (req, res) => {
    try {
        // NOTE: In production, enforce admin check here (e.g., req.user.admin === true)
        const { matchId, gameUid, rank, kills } = req.body;

        if (!matchId || !gameUid || rank === undefined || kills === undefined) {
            return res.status(400).json({ error: 'Missing required distribution data' });
        }

        // Search for the team that owns the given gameUid
        const teamsSnapshot = await db.collection('matches').doc(matchId).collection('teams')
            .where('gameUids', 'array-contains', gameUid)
            .limit(1)
            .get();

        if (teamsSnapshot.empty) {
            return res.status(404).json({ error: 'No registered team found with this Game UID' });
        }

        const teamDocSnapshot = teamsSnapshot.docs[0];
        const teamId = teamDocSnapshot.id;
        const ownerUid = teamDocSnapshot.data().ownerUid;

        await db.runTransaction(async (t) => {
            const matchRef = db.collection('matches').doc(matchId);
            const userRef = db.collection('users').doc(ownerUid);
            const teamRef = matchRef.collection('teams').doc(teamId);

            const [matchSnap, teamSnap, userSnap] = await Promise.all([
                t.get(matchRef), t.get(teamRef), t.get(userRef)
            ]);

            if (!matchSnap.exists || !userSnap.exists) throw new Error('Match or User not found');

            const teamData = teamSnap.data();
            if (teamData.prizeDistributed) {
                throw new Error('Prize has already been distributed to this team');
            }

            const matchData = matchSnap.data();
            const perKillRate = matchData.perKillRate || 0;
            const rankPrizes = matchData.rankPrizes || {};
            const rankPrize = Number(rankPrizes[rank.toString()]) || 0;

            const totalPrize = (kills * perKillRate) + rankPrize;
            const earnedXP = (kills * 10) + 50; // Standard XP Formula

            // Lock distribution & record stats
            t.update(teamRef, {
                prizeDistributed: true,
                finalRank: rank,
                totalKills: kills,
                prizeEarned: totalPrize
            });

            // Credit winnings & XP to team owner
            t.update(userRef, {
                wallet: admin.firestore.FieldValue.increment(totalPrize),
                totalXP: admin.firestore.FieldValue.increment(earnedXP),
                matchesPlayed: admin.firestore.FieldValue.increment(1),
                totalKills: admin.firestore.FieldValue.increment(kills)
            });

            if (totalPrize > 0) {
                const txRef = db.collection('transactions').doc();
                t.set(txRef, {
                    userId: ownerUid,
                    type: 'MATCH_WIN',
                    amount: totalPrize,
                    matchId: matchId,
                    status: 'SUCCESS',
                    timestamp: admin.firestore.FieldValue.serverTimestamp()
                });
            }
        });

        res.json({ success: true, message: 'Prize and XP distributed to user successfully' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Start Server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Esports Backend running on port ${PORT}`);
});
