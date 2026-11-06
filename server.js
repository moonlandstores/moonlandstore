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

app.use(cors());

const ADMIN_PASSCODE = process.env.ADMIN_PASSCODE;
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!ADMIN_PASSCODE || !SESSION_SECRET) {
  console.error('CRITICAL ERROR: ADMIN_PASSCODE and SESSION_SECRET must be set in environment variables (.env).');
  process.exit(1);
}

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

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

function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) {
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

    const orderId = 'MOON-' + crypto.randomBytes(3).toString('hex').toUpperCase();
    const orderRef = db.collection('orders').doc(orderId);

    let verifiedItems = [];
    let calculatedTotal = 0;
    let validRefCode = 'None';

    await db.runTransaction(async (transaction) => {
      const utrQuery = await transaction.get(db.collection('orders').where('utr', '==', utr.trim()).limit(1));
      if (!utrQuery.empty) {
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
        phone: phone.trim(),
        address: address.trim(),
        utr: utr.trim(),
        items: verifiedItems,
        totalAmount: calculatedTotal,
        enteredRefCode: validRefCode,
        utrVerified: false,
        status: 'Payment Verification Pending',
        createdAt: new Date().toISOString()
      };

      transaction.create(orderRef, orderData);
    });

    return res.json({ success: true, orderId });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message || 'Failed to save order' });
  }
});

// ==================== ORDER STATUS UPDATE ROUTES ====================

// 1. Update Single Order Status (or Cancel)
app.put('/api/orders/:id', requireAdmin, adminBodyParser, adminUrlParser, async (req, res) => {
  try {
    const orderId = req.params.id;
    const { status, cancelReason } = req.body;

    if (!status) {
      return res.status(400).json({ success: false, error: 'Status is required' });
    }

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
      status: status.trim(),
      updatedAt: new Date().toISOString()
    };

    if (cancelReason !== undefined) {
      updateData.cancelReason = cancelReason;
    }

    await orderRef.update(updateData);
    res.json({ success: true, message: 'Order status updated successfully' });
  } catch (err) {
    console.error('Error updating order status:', err);
    res.status(500).json({ success: false, error: err.message || 'Failed to update order status' });
  }
});

// 2. Bulk Update Orders Status (Robust Resolution for Document/Field IDs)
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

// ===================================================================

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

const allHtmlPages = [
  'admin-login.html',
  'dash-analytics-9x81.html',
  'manage-orders-8118.html',
  'inventory-products.html',
  'products.html',
  'store.html',
  'track.html',
  'referral.html',
  'referral-payouts.html',
  'settings-gateways.html',
  'customers-crm.html',
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