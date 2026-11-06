require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const admin = require('firebase-admin');
const session = require('express-session');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);

// Enable CORS for all origins (or configure as needed)
app.use(cors());

const ADMIN_PASSCODE = process.env.ADMIN_PASSCODE;
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!ADMIN_PASSCODE || !SESSION_SECRET) {
  console.error('CRITICAL ERROR: ADMIN_PASSCODE and SESSION_SECRET must be set in environment variables (.env).');
  process.exit(1);
}

// Global body limit updated to 10mb to handle product uploads smoothly without 413 errors
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Higher limit specifically for admin product/settings uploads (maintained for consistency)
const adminBodyParser = express.json({ limit: '10mb' });
const adminUrlParser = express.urlencoded({ extended: true, limit: '10mb' });

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true, 
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000 // 1 Day
  }
}));

app.use(express.static(path.join(__dirname, 'public')));

try {
  admin.initializeApp({
    credential: admin.credential.applicationDefault()
  });
} catch (e) {
  console.log('Firebase Initialization Note:', e.message);
}

const db = admin.apps.length ? admin.firestore() : null;

// Startup readiness check: Test Firestore read to ensure connection is live
if (db) {
  db.collection('settings').doc('config').get().then(() => {
    console.log('Database connection verified successfully.');
  }).catch((err) => {
    console.warn('WARNING: Firestore connection test failed:', err.message);
  });
}

function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) {
    return next();
  }
  return res.status(401).json({ success: false, error: 'Unauthorized: Please login first' });
}

// Public rate limiter to prevent DoS and UTR queue spam
const publicApiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 30, // Limit each IP to 30 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many requests from this IP, please try again later.' }
});

// Login rate limiter: count ONLY failures
const loginAttempts = new Map();
function loginRateLimiter(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  const windowMs = 15 * 60 * 1000; // 15 minutes
  const maxAttempts = 5;

  let record = loginAttempts.get(ip) || { count: 0, startTime: now };
  if (now - record.startTime > windowMs) {
    record = { count: 0, startTime: now };
  }

  if (record.count >= maxAttempts) {
    return res.status(429).json({ success: false, error: 'Too many login attempts. Please try again later.' });
  }

  req.loginIpRecord = { ip, record, maxAttempts };
  next();
}

// ==================== ADMIN AUTHENTICATION API ====================

app.post('/api/admin/login', loginRateLimiter, (req, res) => {
  const { passcode } = req.body;
  if (!passcode) {
    return res.status(400).json({ success: false, error: 'Passcode required' });
  }

  const inputBuffer = Buffer.from(passcode);
  const adminBuffer = Buffer.from(ADMIN_PASSCODE);

  if (inputBuffer.length === adminBuffer.length && crypto.timingSafeEqual(inputBuffer, adminBuffer)) {
    req.session.regenerate((err) => {
      if (err) {
        return res.status(500).json({ success: false, error: 'Session regeneration failed' });
      }
      req.session.isAdmin = true;
      return res.json({ success: true, message: 'Authenticated successfully' });
    });
  } else {
    // Increment failure count only on incorrect passcode
    const { ip, record } = req.loginIpRecord;
    record.count++;
    loginAttempts.set(ip, record);
    return res.status(401).json({ success: false, error: 'Invalid Passcode' });
  }
});

app.get('/api/admin/check-session', (req, res) => {
  if (req.session && req.session.isAdmin) {
    return res.json({ authenticated: true });
  }
  return res.status(401).json({ authenticated: false, error: 'Session expired' });
});

app.post('/api/admin/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ success: false, error: 'Logout failed' });
    }
    res.clearCookie('connect.sid');
    return res.json({ success: true, message: 'Logged out successfully' });
  });
});

// ==================== ADMIN ANALYTICS & STATS API ====================

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    if (!db) {
      return res.status(503).json({ error: 'Database service unavailable' });
    }

    const ordersSnapshot = await db.collection('orders').get();
    let totalRevenue = 0;
    let verifiedOrdersCount = 0;
    let pendingOrdersCount = 0;
    let cancelledOrdersCount = 0;
    let referralOrdersCount = 0;
    let totalVerificationTimeMs = 0;
    let verifiedWithTimeCount = 0;
    
    const productSales = {};
    const dailyRevenue = {};

    ordersSnapshot.forEach(doc => {
      const ord = doc.data();
      const status = ord.status || '';
      const totalAmount = Number(ord.totalAmount) || 0;
      const createdAt = new Date(ord.createdAt || Date.now());

      if (status === 'Cancelled' || status === 'Rejected') {
        cancelledOrdersCount++;
      } else if (ord.utrVerified === true || status === 'Order Placed' || status === 'Delivered' || status === 'Shipped') {
        verifiedOrdersCount++;
        totalRevenue += totalAmount;

        const dateStr = createdAt.toISOString().split('T')[0];
        dailyRevenue[dateStr] = (dailyRevenue[dateStr] || 0) + totalAmount;

        if (ord.enteredRefCode && ord.enteredRefCode !== 'None' && ord.enteredRefCode !== 'Direct' && ord.enteredRefCode.trim() !== '') {
          referralOrdersCount++;
        }

        if (ord.verifiedAt) {
          const verifiedAt = new Date(ord.verifiedAt);
          const diffMs = verifiedAt - createdAt;
          if (diffMs > 0) {
            totalVerificationTimeMs += diffMs;
            verifiedWithTimeCount++;
          }
        }

        // Product sales count restricted strictly to verified/completed orders
        if (Array.isArray(ord.items)) {
          ord.items.forEach(item => {
            const pName = item.name || item.title || 'Product';
            const qty = Number(item.quantity) || 1;
            productSales[pName] = (productSales[pName] || 0) + qty;
          });
        }
      } else {
        pendingOrdersCount++;
      }
    });

    const totalOrders = ordersSnapshot.size;
    const conversionRate = totalOrders > 0 ? ((verifiedOrdersCount / totalOrders) * 100).toFixed(1) : 0;
    const avgVerificationTimeMinutes = verifiedWithTimeCount > 0 ? Math.round(totalVerificationTimeMs / verifiedWithTimeCount / (1000 * 60)) : 0;
    const referralSharePercent = verifiedOrdersCount > 0 ? ((referralOrdersCount / verifiedOrdersCount) * 100).toFixed(1) : 0;

    const topProducts = Object.entries(productSales)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    res.json({
      totalRevenue,
      verifiedOrdersCount,
      pendingOrdersCount,
      cancelledOrdersCount,
      conversionRate,
      avgVerificationTimeMinutes,
      topProducts,
      referralSharePercent,
      dailyRevenue
    });
  } catch (err) {
    console.error('Failed to fetch analytics stats:', err);
    res.status(500).json({ error: 'Failed to fetch analytics stats' });
  }
});

// ==================== SETTINGS & GATEWAYS API ====================

app.get('/api/settings', async (req, res) => {
  try {
    if (!db) return res.status(503).json({ error: 'Database service unavailable' });
    const doc = await db.collection('settings').doc('gateways').get();
    if (!doc.exists) {
      return res.status(503).json({ error: 'Payment gateway settings not configured. Payment unavailable.' });
    }
    const data = doc.data();
    if (!data.upiId || data.upiId === 'paymoonland@upi') {
      return res.status(503).json({ error: 'Payment gateway configuration missing. Payment unavailable.' });
    }
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch settings' });
  }
});

app.put('/api/settings', requireAdmin, adminBodyParser, adminUrlParser, async (req, res) => {
  try {
    const { upiId, merchantName, qrCodeUrl } = req.body;
    if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });
    
    const upiRegex = /^[\w.\-]{2,}@[a-zA-Z]{2,}$/;
    if (!upiId || !upiRegex.test(upiId)) {
      return res.status(400).json({ success: false, error: 'Invalid UPI ID format' });
    }

    await db.collection('settings').doc('gateways').set({
      upiId: upiId.trim(),
      merchantName: (merchantName || 'Moonland Store').trim(),
      qrCodeUrl: qrCodeUrl || ''
    }, { merge: true });
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to update settings' });
  }
});

// ==================== PRODUCTS API ====================

app.get('/api/products', async (req, res) => {
  try {
    if (!db) return res.status(503).json({ error: 'Database unavailable' });
    const snapshot = await db.collection('products').get();
    const products = [];
    snapshot.forEach(doc => {
      const data = doc.data();
      products.push({
        id: doc.id,
        name: data.name || '',
        price: Number(data.price) || 0,
        images: data.images || [],
        keyFeatures: data.keyFeatures || '',
        details: data.details || ''
      });
    });
    res.json(products);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

app.post('/api/products', requireAdmin, adminBodyParser, adminUrlParser, async (req, res) => {
  try {
    const { name, price, images, keyFeatures, details } = req.body;
    const numPrice = Number(price);
    if (!name || isNaN(numPrice) || numPrice <= 0) {
      return res.status(400).json({ success: false, error: 'Invalid product data or price' });
    }
    if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });
    
    const docRef = await db.collection('products').add({
      name: name.trim(),
      price: numPrice,
      images: Array.isArray(images) ? images : [],
      keyFeatures: keyFeatures || '',
      details: details || '',
      createdAt: new Date().toISOString()
    });
    res.json({ success: true, productId: docRef.id });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to save product' });
  }
});

app.put('/api/products/:id', requireAdmin, adminBodyParser, adminUrlParser, async (req, res) => {
  try {
    const productId = req.params.id;
    const { name, price, images, keyFeatures, details } = req.body;
    if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });
    
    const numPrice = Number(price);
    const updatePayload = {};
    if (name) updatePayload.name = name.trim();
    if (!isNaN(numPrice)) updatePayload.price = numPrice;
    if (images) updatePayload.images = Array.isArray(images) ? images : [];
    if (keyFeatures !== undefined) updatePayload.keyFeatures = keyFeatures;
    if (details !== undefined) updatePayload.details = details;

    await db.collection('products').doc(productId).update(updatePayload);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to update product' });
  }
});

app.delete('/api/products/:id', requireAdmin, async (req, res) => {
  try {
    const productId = req.params.id;
    if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });
    
    await db.collection('products').doc(productId).delete();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to delete product' });
  }
});

// ==================== TRACK ORDER API (Single Search Box) ====================

app.post('/api/track', publicApiLimiter, async (req, res) => {
  try {
    const { query } = req.body;
    if (!query || typeof query !== 'string' || query.trim() === '') {
      return res.status(400).json({ success: false, error: 'Kripya Order ID ya Mobile Number enter karein.' });
    }
    if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });

    const cleanQuery = query.trim();
    let ordersList = [];

    // 1. Check if query matches exact Order ID document
    const docRef = db.collection('orders').doc(cleanQuery);
    const doc = await docRef.get();
    if (doc.exists) {
      ordersList.push({ id: doc.id, ...doc.data() });
    }

    // 2. Query by phone number if not found or matching phone
    if (ordersList.length === 0) {
      const phoneQuery = await db.collection('orders').where('phone', '==', cleanQuery).get();
      phoneQuery.forEach(d => {
        ordersList.push({ id: d.id, ...d.data() });
      });
    }

    // 3. Fallback search by substring across orders
    if (ordersList.length === 0) {
      const allOrdersSnap = await db.collection('orders').get();
      allOrdersSnap.forEach(d => {
        const data = d.data();
        if (d.id.toLowerCase().includes(cleanQuery.toLowerCase()) || (data.phone && data.phone.includes(cleanQuery))) {
          if (!ordersList.some(o => o.id === d.id)) {
            ordersList.push({ id: d.id, ...data });
          }
        }
      });
    }

    if (ordersList.length === 0) {
      return res.status(404).json({ success: false, error: 'Koi order nahi mila. Kripya sahi Order ID ya Mobile Number dalein.' });
    }

    // Format to return Customer Name, Order ID, and Status only
    const formattedOrders = ordersList.map(ord => ({
      id: ord.id,
      customer: ord.customer || ord.name || 'Valued Customer',
      status: ord.status || (ord.utrVerified ? 'Order Placed' : 'Payment Verification Pending')
    }));

    res.json({ success: true, orders: formattedOrders });
  } catch (err) {
    console.error('Tracking error:', err);
    res.status(500).json({ success: false, error: 'Failed to track order' });
  }
});

// ==================== REFERRAL LOOKUP API (For referral.html) ====================

app.post('/api/referral-lookup', publicApiLimiter, async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone || !/^\d{10}$/.test(phone)) {
      return res.status(400).json({ success: false, error: 'Valid 10-digit phone number required' });
    }
    if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });

    const snapshot = await db.collection('orders').where('phone', '==', phone.trim()).get();
    if (snapshot.empty) {
      return res.status(404).json({ success: false, error: 'No orders found for this phone number.' });
    }

    let userRefCode = null;
    snapshot.forEach(doc => {
      const data = doc.data();
      if (data.userRefCode && data.userRefCode.startsWith('REF-')) {
        userRefCode = data.userRefCode;
      }
    });

    if (!userRefCode) {
      return res.status(404).json({ success: false, error: 'No active referral code generated yet. Place a verified order first.' });
    }

    res.json({ success: true, userRefCode });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to lookup referral code' });
  }
});

// ==================== ORDERS API ====================

app.get('/api/orders', requireAdmin, async (req, res) => {
  try {
    if (!db) return res.status(503).json({ error: 'Database unavailable' });
    
    const statusFilter = req.query.status;
    let query = db.collection('orders');
    
    if (statusFilter === 'pending') {
      query = query.where('utrVerified', '==', false);
    }
    
    const snapshot = await query.orderBy('createdAt', 'desc').limit(200).get();
    const orders = [];
    snapshot.forEach(doc => {
      orders.push({ id: doc.id, ...doc.data() });
    });
    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

app.post('/api/orders', publicApiLimiter, async (req, res) => {
  try {
    const { customer, phone, address, utr, items, enteredRefCode, upiId } = req.body;

    if (!customer || !phone || !address || !utr) {
      return res.status(400).json({ success: false, error: 'All fields are required' });
    }
    if (!/^\d{10}$/.test(phone)) {
      return res.status(400).json({ success: false, error: 'Invalid 10-digit mobile number' });
    }
    if (!/^\d{12}$/.test(utr)) {
      return res.status(400).json({ success: false, error: 'Invalid 12-digit UTR reference number' });
    }
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ success: false, error: 'Cart is empty' });
    }

    if (!db) {
      return res.status(503).json({ success: false, error: 'Database unavailable. Order could not be placed.' });
    }

    // Secure collision-resistant Order ID using cryptographic random bytes
    const orderId = 'MOON-' + crypto.randomBytes(3).toString('hex').toUpperCase();
    const orderRef = db.collection('orders').doc(orderId);

    let verifiedItems = [];
    let calculatedTotal = 0;
    let validRefCode = 'None';
    const cleanUpiId = upiId && /^[\w.\-]{2,}@[a-zA-Z]{2,}$/.test(upiId) ? upiId.trim() : '';

    await db.runTransaction(async (transaction) => {
      // Check UTR uniqueness
      const utrQuery = await transaction.get(db.collection('orders').where('utr', '==', utr.trim()).limit(1));
      if (!utrQuery.empty) {
        throw new Error('This UTR number has already been used.');
      }

      for (let item of items) {
        if (!item.id) {
          throw new Error('Invalid cart item: Missing product ID.');
        }
        const prodDocRef = db.collection('products').doc(item.id);
        const prodDoc = await transaction.get(prodDocRef);
        
        if (!prodDoc.exists) {
          throw new Error(`Product with ID ${item.id} does not exist in inventory.`);
        }

        const prodData = prodDoc.data();
        const unitPrice = Number(prodData.price) || 0;
        let qty = parseInt(item.quantity, 10) || 1;
        
        if (qty < 1) qty = 1;
        if (qty > 50) qty = 50;

        calculatedTotal += unitPrice * qty;
        verifiedItems.push({
          id: item.id,
          name: prodData.name || prodData.title || 'Product',
          price: unitPrice,
          quantity: qty
        });
      }

      if (calculatedTotal <= 0) {
        throw new Error('Order total cannot be zero or negative.');
      }

      // Safe Referral Validation
      if (enteredRefCode && enteredRefCode !== 'None' && enteredRefCode.trim() !== '') {
        const cleanRefCode = enteredRefCode.trim();
        const refQuery = await transaction.get(db.collection('orders').where('userRefCode', '==', cleanRefCode).limit(1));
        if (!refQuery.empty) {
          const referrerOrder = refQuery.docs[0].data(); // Fixed QuerySnapshot data extraction bug
          if (referrerOrder.phone === phone.trim()) {
            throw new Error('Self-referral is not allowed.');
          }
          validRefCode = cleanRefCode;
        } else {
          throw new Error('Invalid referral code.'); // Strictly reject non-existent referral codes
        }
      }

      const orderData = {
        id: orderId,
        customer: customer.trim(),
        phone: phone.trim(),
        address: address.trim(),
        utr: utr.trim(),
        items: verifiedItems,
        totalAmount: calculatedTotal,
        enteredRefCode: validRefCode,
        upiId: cleanUpiId,
        utrVerified: false,
        status: 'Payment Verification Pending',
        createdAt: new Date().toISOString()
      };

      // Use transaction.create to ensure absolute uniqueness and prevent overwriting collisions
      transaction.create(orderRef, orderData);
    });

    return res.json({ success: true, orderId });
  } catch (err) {
    console.error('Error saving order:', err.message);
    res.status(400).json({ success: false, error: err.message || 'Failed to save order' });
  }
});

const ORDER_EDITABLE = [
  'status', 'cancelReason', 'utrVerified', 'userRefCode',
  'customer', 'name', 'phone', 'address', 'payoutStatus', 'payoutPaidAt', 'upiId'
];
const pickOrderFields = (o) => Object.fromEntries(ORDER_EDITABLE.filter(k => k in o).map(k => [k, o[k]]));

app.put('/api/orders/bulk-status', requireAdmin, async (req, res) => {
  try {
    const { ids, status } = req.body;
    if (!Array.isArray(ids) || !ids.length || ids.length > 400 || typeof status !== 'string') {
      return res.status(400).json({ success: false, error: 'Invalid payload' });
    }
    if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });

    const batch = db.batch();
    ids.forEach(id => {
      const docRef = db.collection('orders').doc(String(id));
      batch.update(docRef, { status: status.trim() });
    });
    await batch.commit();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Bulk update failed' });
  }
});

// Idempotent & Transactional Approve Order Route
app.put('/api/orders/:id/approve', requireAdmin, async (req, res) => {
  try {
    if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });
    const orderId = req.params.id;
    const orderRef = db.collection('orders').doc(orderId);
    let generatedRefCode = '';

    await db.runTransaction(async (transaction) => {
      const doc = await transaction.get(orderRef);
      if (!doc.exists) {
        throw new Error('Order not found.');
      }
      const ord = doc.data();
      if (ord.utrVerified === true) {
        // Idempotent return if already approved
        generatedRefCode = ord.userRefCode || ('REF-' + Math.floor(100000 + Math.random() * 900000));
        return;
      }
      if (ord.status === 'Cancelled' || ord.status === 'Rejected') {
        throw new Error('Cannot approve a cancelled or rejected order.');
      }

      // Check if user already has a generated referral code from prior orders, else create new
      const userPhone = ord.phone;
      const existingUserQuery = await transaction.get(db.collection('orders').where('phone', '==', userPhone).where('userRefCode', '!=', 'None').limit(1));
      
      if (!existingUserQuery.empty && existingUserQuery.docs[0].data().userRefCode) {
        generatedRefCode = existingUserQuery.docs[0].data().userRefCode;
      } else {
        generatedRefCode = 'REF-' + Math.floor(100000 + Math.random() * 900000);
      }

      transaction.update(orderRef, {
        utrVerified: true,
        status: 'Order Placed',
        userRefCode: generatedRefCode,
        verifiedAt: new Date().toISOString()
      });
    });

    res.json({ success: true, userRefCode: generatedRefCode });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message || 'Failed to approve order' });
  }
});

app.put('/api/orders/:id', requireAdmin, async (req, res) => {
  try {
    if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });
    const docRef = db.collection('orders').doc(req.params.id);
    const doc = await docRef.get();
    if (!doc.exists) {
      return res.status(404).json({ success: false, error: 'Order not found' });
    }
    await docRef.update(pickOrderFields(req.body));
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to update order' });
  }
});

app.delete('/api/orders/:id', requireAdmin, async (req, res) => {
  try {
    if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });
    const docRef = db.collection('orders').doc(req.params.id);
    const doc = await docRef.get();
    if (!doc.exists) {
      return res.status(404).json({ success: false, error: 'Order not found' });
    }
    await docRef.update({
      status: 'Rejected',
      utrVerified: false
    });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to update order' });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running securely at http://localhost:${PORT}`);
});