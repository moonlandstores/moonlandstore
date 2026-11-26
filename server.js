require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const admin = require('firebase-admin');
const session = require('express-session');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);

app.use(cors());

const ADMIN_PASSCODE = process.env.ADMIN_PASSCODE;
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!ADMIN_PASSCODE || !SESSION_SECRET) {
  console.error('CRITICAL ERROR: ADMIN_PASSCODE and SESSION_SECRET must be set in environment variables (.env).');
  process.exit(1);
}

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

const adminBodyParser = express.json({ limit: '50mb' });
const adminUrlParser = express.urlencoded({ extended: true, limit: '50mb' });

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

const publicDir = path.join(__dirname, 'public');
app.use(express.static(publicDir, {
  extensions: ['html']
}));

try {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n') : undefined
    })
  });
} catch (e) {
  console.log('Firebase Initialization Note:', e.message);
}

const db = admin.apps.length ? admin.firestore() : null;

if (db) {
  db.collection('settings').doc('config').get().then(() => {
    console.log('Database connection verified successfully.');
  }).catch((err) => {
    console.warn('WARNING: Firestore connection test failed:', err.message);
  });
}

function escapeHtmlAttr(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function getBaseUrl(req) {
  const proto = (req.headers['x-forwarded-proto'] || req.protocol || 'https').split(',')[0].trim();
  const host = req.get('host');
  return `${proto}://${host}`;
}

function resolveProductPageFile() {
  const primaryPage = path.join(publicDir, 'products.html');
  if (fs.existsSync(primaryPage)) return 'products.html';
  return 'product.html';
}

function sendProductPageFallback(res) {
  const pageName = resolveProductPageFile();
  return res.status(200).sendFile(path.join(publicDir, pageName), (err) => {
    if (err && !res.headersSent) {
      res.status(200).redirect('/store.html');
    }
  });
}

async function getProductById(productId) {
  if (!db || !productId) return null;
  const cleanId = String(productId).trim();
  const doc = await db.collection('products').doc(cleanId).get();
  if (!doc.exists) return null;
  const data = doc.data();
  return {
    id: doc.id,
    name: data.name || 'Moonland Store Product',
    price: Number(data.price) || 0,
    images: Array.isArray(data.images) ? data.images : [],
    keyFeatures: data.keyFeatures || '',
    details: data.details || ''
  };
}

function isAdminAuthenticated(req) {
  return Boolean(req.session && req.session.isAdmin);
}

function requireAdmin(req, res, next) {
  if (isAdminAuthenticated(req)) {
    return next();
  }
  return res.status(401).json({ success: false, error: 'Unauthorized: Please login first' });
}

const publicApiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many requests from this IP, please try again later.' }
});

const loginAttempts = new Map();
function loginRateLimiter(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  const windowMs = 15 * 60 * 1000;
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
    const { ip, record } = req.loginIpRecord;
    record.count++;
    loginAttempts.set(ip, record);
    return res.status(401).json({ success: false, error: 'Invalid Passcode' });
  }
});

app.get('/api/admin/check-session', (req, res) => {
  if (isAdminAuthenticated(req)) {
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

app.get('/api/settings', async (req, res) => {
  try {
    if (!db) return res.status(503).json({ error: 'Database service unavailable' });
    const doc = await db.collection('settings').doc('gateways').get();
    if (!doc.exists) {
      return res.status(503).json({ error: 'Payment gateway settings not configured.' });
    }
    const data = doc.data();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch settings' });
  }
});

app.put('/api/settings', requireAdmin, adminBodyParser, adminUrlParser, async (req, res) => {
  try {
    const { upiId, merchantName, qrCodeUrl } = req.body;
    if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });

    await db.collection('settings').doc('gateways').set({
      upiId: upiId ? upiId.trim() : '',
      merchantName: (merchantName || 'Moonland Store').trim(),
      qrCodeUrl: qrCodeUrl || ''
    }, { merge: true });

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to update settings' });
  }
});

// ==================== CHECKOUT PHONE LEADS ROUTES ====================

app.post('/api/checkout-leads', publicApiLimiter, async (req, res) => {
  try {
    if (!db) {
      return res.status(503).json({ success: false, error: 'Database unavailable' });
    }

    const cleanPhone = String(req.body.phone || '').replace(/\D/g, '');
    if (!/^\d{10}$/.test(cleanPhone)) {
      return res.status(400).json({ success: false, error: 'Valid 10-digit mobile number required' });
    }

    const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
    const address = typeof req.body.address === 'string' ? req.body.address.trim() : '';
    const upiId = typeof req.body.upiId === 'string' ? req.body.upiId.trim() : '';
    const referralCode = typeof req.body.referralCode === 'string' ? req.body.referralCode.trim() : '';

    const leadRef = db.collection('checkout_leads').doc(cleanPhone);
    const existingDoc = await leadRef.get();
    const nowIso = new Date().toISOString();

    const payload = {
      phone: cleanPhone,
      source: 'checkout_form',
      updatedAt: nowIso
    };

    if (!existingDoc.exists) {
      payload.createdAt = nowIso;
      payload.orderCompleted = false;
    }
    if (name) payload.name = name;
    if (address) payload.address = address;
    if (upiId) payload.upiId = upiId;
    if (referralCode) payload.referralCode = referralCode;

    await leadRef.set(payload, { merge: true });
    return res.json({ success: true });
  } catch (err) {
    console.error('Checkout lead save error:', err);
    return res.status(500).json({ success: false, error: 'Failed to save phone number' });
  }
});

app.get('/api/checkout-leads', requireAdmin, async (req, res) => {
  try {
    if (!db) {
      return res.status(503).json({ success: false, error: 'Database unavailable' });
    }

    const snapshot = await db.collection('checkout_leads').get();
    const leads = [];
    snapshot.forEach(doc => {
      leads.push({ id: doc.id, ...doc.data() });
    });

    leads.sort((a, b) => new Date(b.updatedAt || b.createdAt || 0) - new Date(a.updatedAt || a.createdAt || 0));
    return res.json(leads);
  } catch (err) {
    console.error('Failed to fetch checkout leads:', err);
    return res.status(500).json({ success: false, error: 'Failed to fetch checkout leads' });
  }
});

// ==================== WHATSAPP & SOCIAL PREVIEW ROUTES ====================

app.get('/api/products/:id/og-image', async (req, res) => {
  try {
    const product = await getProductById(req.params.id);
    const firstImg = product && Array.isArray(product.images) && product.images[0] ? product.images[0] : '';

    if (!firstImg) {
      return res.redirect('/logo.png?v=999');
    }

    if (firstImg.startsWith('data:')) {
      const match = firstImg.match(/^data:(image\/[a-zA-Z0-9.+-]+);base64,(.+)$/);
      if (!match) {
        return res.redirect('/logo.png?v=999');
      }
      const mimeType = match[1];
      const imgBuffer = Buffer.from(match[2], 'base64');
      res.setHeader('Content-Type', mimeType);
      res.setHeader('Cache-Control', 'public, max-age=86400');
      return res.send(imgBuffer);
    }

    if (/^https?:\/\//i.test(firstImg) || firstImg.startsWith('/')) {
      return res.redirect(firstImg);
    }

    return res.redirect('/logo.png?v=999');
  } catch (err) {
    console.error('OG image error:', err);
    return res.redirect('/logo.png?v=999');
  }
});

function renderProductPreviewHtml(req, res, productId) {
  getProductById(productId)
    .then((product) => {
      const baseUrl = getBaseUrl(req);
      const cleanId = encodeURIComponent(productId || '');
      const refParam = (req.query.ref || req.query.code || '').trim();
      const refQuery = refParam ? `&ref=${encodeURIComponent(refParam)}` : '';
      const pageFile = resolveProductPageFile();
      const clientTargetUrl = `${baseUrl}/${pageFile}?id=${cleanId}${refQuery}`;

      if (!product) {
        return sendProductPageFallback(res);
      }

      const titleText = `${product.name} — ₹${product.price.toLocaleString('en-IN')} | MOONLAND STORE`;
      const descText = (product.keyFeatures || product.details || 'Buy original products on Moonland Store.').slice(0, 180);
      const ogImageUrl = `${baseUrl}/api/products/${cleanId}/og-image`;

      const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtmlAttr(titleText)}</title>
  <meta property="og:type" content="product">
  <meta property="og:site_name" content="MOONLAND STORE">
  <meta property="og:title" content="${escapeHtmlAttr(titleText)}">
  <meta property="og:description" content="${escapeHtmlAttr(descText)}">
  <meta property="og:image" content="${escapeHtmlAttr(ogImageUrl)}">
  <meta property="og:image:secure_url" content="${escapeHtmlAttr(ogImageUrl)}">
  <meta property="og:url" content="${escapeHtmlAttr(clientTargetUrl)}">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="${escapeHtmlAttr(titleText)}">
  <meta name="twitter:description" content="${escapeHtmlAttr(descText)}">
  <meta name="twitter:image" content="${escapeHtmlAttr(ogImageUrl)}">
  <script>window.location.replace(${JSON.stringify(clientTargetUrl)});</script>
</head>
<body style="background:#050505;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;">
  <p>Opening <a href="${escapeHtmlAttr(clientTargetUrl)}" style="color:#38bdf8;">${escapeHtmlAttr(product.name)}</a>...</p>
</body>
</html>`;
      return res.status(200).send(html);
    })
    .catch(() => {
      return sendProductPageFallback(res);
    });
}

app.get('/p/:id', (req, res) => {
  renderProductPreviewHtml(req, res, req.params.id);
});

app.get('/product', (req, res) => {
  const id = req.query.id || req.query.product;
  if (id) {
    return renderProductPreviewHtml(req, res, id);
  }
  return sendProductPageFallback(res);
});

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

app.post('/api/track', publicApiLimiter, async (req, res) => {
  try {
    const { query } = req.body;
    if (!query || typeof query !== 'string' || query.trim() === '') {
      return res.status(400).json({ success: false, error: 'Kripya Order ID ya Mobile Number enter karein.' });
    }
    if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });

    const cleanQuery = query.trim();
    let ordersList = [];

    const docRef = db.collection('orders').doc(cleanQuery);
    const doc = await docRef.get();
    if (doc.exists) {
      ordersList.push({ id: doc.id, ...doc.data() });
    }

    if (ordersList.length === 0) {
      const phoneQuery = await db.collection('orders').where('phone', '==', cleanQuery).get();
      phoneQuery.forEach(d => {
        ordersList.push({ id: d.id, ...d.data() });
      });
    }

    if (ordersList.length === 0) {
      return res.status(404).json({ success: false, error: 'Koi order nahi mila.' });
    }

    const formattedOrders = ordersList.map(ord => ({
      id: ord.id,
      customer: ord.customer || ord.name || 'Valued Customer',
      status: ord.status || (ord.utrVerified ? 'Order Placed' : 'Payment Verification Pending')
    }));

    res.json({ success: true, orders: formattedOrders });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to track order' });
  }
});

// ==================== AFFILIATE PARTNERS API ROUTES ====================

app.get('/api/affiliate-partners', publicApiLimiter, async (req, res) => {
  try {
    if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });

    if (isAdminAuthenticated(req)) {
      const snapshot = await db.collection('affiliate_partners').orderBy('createdAt', 'desc').get();
      const partners = [];
      snapshot.forEach(doc => {
        partners.push({ id: doc.id, ...doc.data() });
      });
      return res.json(partners);
    }

    const cleanPhone = String(req.query.phone || '').replace(/\D/g, '');
    if (!/^\d{10}$/.test(cleanPhone)) {
      return res.json([]);
    }

    const snap = await db.collection('affiliate_partners').where('phone', '==', cleanPhone).limit(1).get();
    if (snap.empty) {
      return res.json([]);
    }

    const doc = snap.docs[0];
    const data = doc.data();
    return res.json([{
      id: doc.id,
      name: data.name || '',
      phone: data.phone || cleanPhone,
      status: data.status || 'Pending',
      referralCode: (data.status === 'Approved') ? (data.referralCode || '') : ''
    }]);
  } catch (err) {
    console.error('Failed to fetch affiliate partners:', err);
    res.status(500).json({ success: false, error: 'Failed to fetch affiliate partners' });
  }
});

app.post('/api/affiliate-partners', publicApiLimiter, async (req, res) => {
  try {
    if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });
    const { id, name, phone, address, upiId } = req.body;
    const cleanPhone = String(phone || '').replace(/\D/g, '');

    if (!name || !cleanPhone || !/^\d{10}$/.test(cleanPhone) || !address || !upiId) {
      return res.status(400).json({ success: false, error: 'Please provide valid Name, 10-digit Phone, Address, and UPI ID.' });
    }

    const existingSnap = await db.collection('affiliate_partners').where('phone', '==', cleanPhone).limit(1).get();
    if (!existingSnap.empty) {
      const existingDoc = existingSnap.docs[0];
      const existingData = existingDoc.data();
      return res.status(409).json({
        success: false,
        error: 'This mobile number is already registered as an Affiliate Partner.',
        partner: {
          id: existingDoc.id,
          name: existingData.name || '',
          phone: existingData.phone || cleanPhone,
          status: existingData.status || 'Pending',
          referralCode: (existingData.status === 'Approved') ? (existingData.referralCode || '') : ''
        }
      });
    }

    const partnerId = (typeof id === 'string' && id.trim()) ? id.trim() : 'AFF-' + crypto.randomBytes(3).toString('hex').toUpperCase();
    const newPartner = {
      id: partnerId,
      name: String(name).trim(),
      phone: cleanPhone,
      address: String(address).trim(),
      upiId: String(upiId).trim(),
      status: 'Pending',
      referralCode: '',
      createdAt: new Date().toISOString()
    };

    await db.collection('affiliate_partners').doc(partnerId).set(newPartner);
    res.json({ success: true, partner: newPartner });
  } catch (err) {
    console.error('Failed to register affiliate partner:', err);
    res.status(500).json({ success: false, error: 'Failed to register affiliate partner' });
  }
});

app.put('/api/affiliate-partners/:id', requireAdmin, adminBodyParser, adminUrlParser, async (req, res) => {
  try {
    if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });
    const partnerId = String(req.params.id || '').trim();
    const { status, referralCode, approvedAt } = req.body;

    const docRef = db.collection('affiliate_partners').doc(partnerId);
    const doc = await docRef.get();
    if (!doc.exists) {
      return res.status(404).json({ success: false, error: 'Affiliate partner not found' });
    }

    const existing = doc.data();
    const nextStatus = status ? String(status).trim() : 'Approved';
    const finalCode = nextStatus === 'Approved'
      ? ((typeof referralCode === 'string' && referralCode.trim())
        ? referralCode.trim()
        : (existing.referralCode || ('AFF-' + Math.floor(100000 + Math.random() * 900000))))
      : '';

    const updatePayload = {
      status: nextStatus,
      referralCode: finalCode,
      updatedAt: new Date().toISOString()
    };

    if (nextStatus === 'Approved') {
      updatePayload.approvedAt = approvedAt || new Date().toISOString();
    } else if (nextStatus === 'Rejected') {
      updatePayload.rejectedAt = new Date().toISOString();
    }

    await docRef.update(updatePayload);
    res.json({ success: true, partner: { id: partnerId, ...existing, ...updatePayload } });
  } catch (err) {
    console.error('Failed to update affiliate partner:', err);
    res.status(500).json({ success: false, error: 'Failed to update affiliate partner' });
  }
});

app.get('/api/orders', publicApiLimiter, async (req, res) => {
  try {
    if (!db) return res.status(503).json({ error: 'Database unavailable' });

    const snapshot = await db.collection('orders').get();
    const orders = [];
    snapshot.forEach(doc => {
      orders.push({ id: doc.id, ...doc.data() });
    });

    orders.sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
    res.json(orders);
  } catch (err) {
    console.error('Failed to fetch orders:', err);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

app.post('/api/orders', publicApiLimiter, async (req, res) => {
  try {
    const customer = req.body.customer || req.body.customerName || req.body.name;
    const phone = req.body.phone || req.body.mobile;
    const address = req.body.address;
    const utrVal = req.body.utr || req.body.utrNumber;
    const items = req.body.items;
    const enteredRefCode = req.body.enteredRefCode || req.body.referralCode;
    const upiId = req.body.upiId || req.body.customerUpi;

    if (!customer || !phone || !address || !utrVal) {
      return res.status(400).json({ success: false, error: 'All fields (Customer, Phone, Address, UTR) are required' });
    }

    if (!items || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ success: false, error: 'Cart is empty or invalid items provided' });
    }

    const orderId = 'MOON-' + crypto.randomBytes(3).toString('hex').toUpperCase();
    const orderRef = db.collection('orders').doc(orderId);

    let verifiedItems = [];
    let calculatedTotal = 0;

    let validRefCode = 'None';
    if (enteredRefCode && typeof enteredRefCode === 'string') {
      const trimmedCode = enteredRefCode.trim();
      if (trimmedCode !== '' && trimmedCode.toLowerCase() !== 'none' && trimmedCode.toLowerCase() !== 'direct') {
        validRefCode = trimmedCode;
      }
    }

    await db.runTransaction(async (transaction) => {
      const utrQuery = await transaction.get(db.collection('orders').where('utr', '==', utrVal.trim()).limit(1));
      const utrNumberQuery = await transaction.get(db.collection('orders').where('utrNumber', '==', utrVal.trim()).limit(1));

      if (!utrQuery.empty || !utrNumberQuery.empty) {
        throw new Error('This UTR number has already been used.');
      }

      for (let item of items) {
        const prodDocRef = db.collection('products').doc(item.id);
        const prodDoc = await transaction.get(prodDocRef);

        if (!prodDoc.exists) {
          throw new Error(`Product with ID ${item.id} does not exist.`);
        }

        const prodData = prodDoc.data();
        const unitPrice = Number(prodData.price) || 0;
        let qty = parseInt(item.quantity, 10) || 1;

        calculatedTotal += unitPrice * qty;
        verifiedItems.push({
          id: item.id,
          name: prodData.name || 'Product',
          price: unitPrice,
          quantity: qty
        });
      }

      const orderData = {
        id: orderId,
        customer: customer.trim(),
        customerName: customer.trim(),
        phone: phone.trim(),
        address: address.trim(),
        upiId: upiId ? upiId.trim() : '',
        customerUpi: upiId ? upiId.trim() : '',
        utr: utrVal.trim(),
        utrNumber: utrVal.trim(),
        items: verifiedItems,
        totalAmount: calculatedTotal,
        enteredRefCode: validRefCode,
        referralCode: validRefCode,
        utrVerified: false,
        status: 'Payment Verification Pending',
        createdAt: new Date().toISOString()
      };

      transaction.create(orderRef, orderData);
    });

    const cleanLeadPhone = String(phone).replace(/\D/g, '');
    if (/^\d{10}$/.test(cleanLeadPhone)) {
      await db.collection('checkout_leads').doc(cleanLeadPhone).set({
        phone: cleanLeadPhone,
        name: customer.trim(),
        address: address.trim(),
        upiId: upiId ? upiId.trim() : '',
        referralCode: validRefCode === 'None' ? '' : validRefCode,
        orderCompleted: true,
        lastOrderId: orderId,
        updatedAt: new Date().toISOString()
      }, { merge: true }).catch(() => {});
    }

    return res.json({ success: true, orderId });
  } catch (err) {
    console.error('Order creation error:', err.message);
    res.status(400).json({ success: false, error: err.message || 'Failed to save order' });
  }
});

// ==================== ORDER STATUS & CRM UPDATE ROUTES ====================

app.put('/api/orders/bulk-status', requireAdmin, adminBodyParser, adminUrlParser, async (req, res) => {
  try {
    const { ids, status } = req.body;

    if (!ids || !Array.isArray(ids) || ids.length === 0 || !status) {
      return res.status(400).json({ success: false, error: 'Invalid data provided for bulk update' });
    }

    if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });

    const batch = db.batch();
    for (const orderId of ids) {
      if (!orderId) continue;
      const cleanId = orderId.trim();

      const orderRef = db.collection('orders').doc(cleanId);
      const docSnap = await orderRef.get();

      if (docSnap.exists) {
        batch.update(orderRef, {
          status: status.trim(),
          updatedAt: new Date().toISOString()
        });
      } else {
        const querySnap = await db.collection('orders').where('id', '==', cleanId).get();
        if (!querySnap.empty) {
          querySnap.forEach(matchedDoc => {
            batch.update(matchedDoc.ref, {
              status: status.trim(),
              updatedAt: new Date().toISOString()
            });
          });
        } else {
          batch.set(orderRef, {
            status: status.trim(),
            updatedAt: new Date().toISOString()
          }, { merge: true });
        }
      }
    }

    await batch.commit();
    res.json({ success: true, message: 'Bulk status updated successfully' });
  } catch (err) {
    console.error('Error in bulk update:', err);
    res.status(500).json({ success: false, error: err.message || 'Bulk update failed' });
  }
});

app.put('/api/referrals/:id', publicApiLimiter, adminBodyParser, adminUrlParser, async (req, res) => {
  try {
    const orderId = req.params.id;
    const { payoutStatus, payoutPaidAt } = req.body;

    if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });

    const cleanId = orderId.trim();
    let orderRef = db.collection('orders').doc(cleanId);
    let doc = await orderRef.get();

    if (!doc.exists) {
      const querySnap = await db.collection('orders').where('id', '==', cleanId).limit(1).get();
      if (!querySnap.empty) {
        orderRef = querySnap.docs[0].ref;
      } else {
        return res.status(404).json({ success: false, error: 'Order not found' });
      }
    }

    const updatePayload = {
      payoutStatus: payoutStatus ? payoutStatus.trim() : 'Paid',
      updatedAt: new Date().toISOString()
    };

    if (payoutPaidAt !== undefined) {
      updatePayload.payoutPaidAt = payoutPaidAt;
    }

    await orderRef.update(updatePayload);

    res.json({ success: true, message: 'Payout status updated successfully' });
  } catch (err) {
    console.error('Error updating payout status:', err);
    res.status(500).json({ success: false, error: err.message || 'Failed to update payout status' });
  }
});

app.put('/api/orders/:id', requireAdmin, adminBodyParser, adminUrlParser, async (req, res) => {
  try {
    const orderId = req.params.id;
    const { customer, name, phone, address, referralId, enteredRefCode, status, cancelReason } = req.body;

    if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });

    const cleanId = orderId.trim();
    let orderRef = db.collection('orders').doc(cleanId);
    let doc = await orderRef.get();

    if (!doc.exists) {
      const querySnap = await db.collection('orders').where('id', '==', cleanId).limit(1).get();
      if (!querySnap.empty) {
        orderRef = querySnap.docs[0].ref;
      } else {
        return res.status(404).json({ success: false, error: 'Order not found' });
      }
    }

    const updateData = {
      updatedAt: new Date().toISOString()
    };

    if (customer !== undefined) updateData.customer = customer.trim();
    if (name !== undefined) updateData.name = name.trim();
    if (phone !== undefined) updateData.phone = phone.trim();
    if (address !== undefined) updateData.address = address.trim();
    if (referralId !== undefined) updateData.userRefCode = referralId.trim();
    if (enteredRefCode !== undefined) updateData.enteredRefCode = enteredRefCode.trim();
    if (status !== undefined) updateData.status = status.trim();
    if (cancelReason !== undefined) updateData.cancelReason = cancelReason;

    await orderRef.update(updateData);
    res.json({ success: true, message: 'Details updated successfully' });
  } catch (err) {
    console.error('Error updating details:', err);
    res.status(500).json({ success: false, error: err.message || 'Failed to update customer details on server' });
  }
});

app.delete('/api/orders/:id', requireAdmin, async (req, res) => {
  try {
    const orderId = req.params.id;
    if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });

    const cleanId = orderId.trim();
    let orderRef = db.collection('orders').doc(cleanId);
    let doc = await orderRef.get();

    if (!doc.exists) {
      const querySnap = await db.collection('orders').where('id', '==', cleanId).limit(1).get();
      if (!querySnap.empty) {
        orderRef = querySnap.docs[0].ref;
      } else {
        return res.status(404).json({ success: false, error: 'Order not found' });
      }
    }

    await orderRef.update({
      status: 'Rejected',
      utrVerified: false,
      updatedAt: new Date().toISOString()
    });

    res.json({ success: true, message: 'Order rejected successfully' });
  } catch (err) {
    console.error('Error rejecting record:', err);
    res.status(500).json({ success: false, error: err.message || 'Failed to reject record on server' });
  }
});

app.put('/api/orders/:id/approve', requireAdmin, async (req, res) => {
  try {
    if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });
    const orderId = req.params.id;
    const orderRef = db.collection('orders').doc(orderId);
    let generatedRefCode = '';

    await db.runTransaction(async (transaction) => {
      const doc = await transaction.get(orderRef);
      if (!doc.exists) throw new Error('Order not found.');
      const ord = doc.data();

      if (ord.utrVerified === true) {
        generatedRefCode = ord.userRefCode || ('REF-' + Math.floor(100000 + Math.random() * 900000));
        return;
      }

      generatedRefCode = 'REF-' + Math.floor(100000 + Math.random() * 900000);

      transaction.update(orderRef, {
        utrVerified: true,
        status: 'Order Placed',
        userRefCode: generatedRefCode,
        verifiedAt: new Date().toISOString()
      });
    });

    res.json({ success: true, userRefCode: generatedRefCode });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// ==================== SEO SITEMAP & ROBOTS ROUTES ====================

app.get('/robots.txt', (req, res) => {
  const baseUrl = getBaseUrl(req);
  const robots = [
    'User-agent: *',
    'Allow: /',
    'Disallow: /admin-login.html',
    'Disallow: /customers-crm.html',
    'Disallow: /dash-analytics-9x81.html',
    'Disallow: /inventory-products.html',
    'Disallow: /manage-orders-8118.html',
    'Disallow: /referral-payouts.html',
    'Disallow: /settings-gateways.html',
    'Disallow: /utr-verification.html',
    'Disallow: /leads-vault-7k49.html',
    'Disallow: /order.html',
    '',
    `Sitemap: ${baseUrl}/sitemap.xml`
  ].join('\n');

  res.type('text/plain').send(robots);
});

app.get('/sitemap.xml', async (req, res) => {
  try {
    const baseUrl = getBaseUrl(req);
    const today = new Date().toISOString().split('T')[0];

    const staticUrls = [
      { loc: `${baseUrl}/`, changefreq: 'daily', priority: '1.0' },
      { loc: `${baseUrl}/store.html`, changefreq: 'daily', priority: '0.9' },
      { loc: `${baseUrl}/products.html`, changefreq: 'daily', priority: '0.8' },
      { loc: `${baseUrl}/referral.html`, changefreq: 'weekly', priority: '0.8' },
      { loc: `${baseUrl}/track.html`, changefreq: 'weekly', priority: '0.6' },
      { loc: `${baseUrl}/about.html`, changefreq: 'monthly', priority: '0.6' }
    ];

    const productUrls = [];
    if (db) {
      const snapshot = await db.collection('products').get();
      snapshot.forEach(doc => {
        productUrls.push({
          loc: `${baseUrl}/p/${encodeURIComponent(doc.id)}`,
          changefreq: 'daily',
          priority: '0.85'
        });
      });
    }

    const allUrls = [...staticUrls, ...productUrls];
    const xmlItems = allUrls.map(u => `  <url>
    <loc>${escapeHtmlAttr(u.loc)}</loc>
    <lastmod>${today}</lastmod>
    <changefreq>${u.changefreq}</changefreq>
    <priority>${u.priority}</priority>
  </url>`).join('\n');

    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${xmlItems}
</urlset>`;

    res.header('Content-Type', 'application/xml');
    res.send(xml);
  } catch (err) {
    console.error('Sitemap generation error:', err);
    res.status(500).type('text/plain').send('Failed to generate sitemap');
  }
});

const allHtmlPages = [
  'admin-login.html',
  'dash-analytics-9x81.html',
  'manage-orders-8118.html',
  'inventory-products.html',
  'products.html',
  'product.html',
  'store.html',
  'track.html',
  'referral.html',
  'referral-payouts.html',
  'settings-gateways.html',
  'customers-crm.html',
  'leads-vault-7k49.html',
  'utr-verification.html',
  'about.html',
  'order.html'
];

allHtmlPages.forEach(page => {
  app.get(`/${page}`, (req, res) => {
    res.sendFile(path.join(publicDir, page));
  });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(publicDir, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running securely at http://localhost:${PORT}`);
});
