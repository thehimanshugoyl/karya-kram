// Smart Event & Ticket Booking – Express + MongoDB (Mongoose)
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const { MONGO_URI = 'mongodb://127.0.0.1:27017/smart_events', JWT_SECRET = 'change-me', PORT = 3000 } = process.env;
const { Schema, model } = mongoose;
const SHOW_OTP = process.env.SHOW_OTP !== 'false'; // demo: show the code on screen. Set SHOW_OTP=false in production.
const ref = (m) => ({ type: Schema.Types.ObjectId, ref: m });

/* ---------- Models ---------- */
const User = model('User', new Schema({
  name: String,
  email: { type: String, unique: true, lowercase: true },
  password: String,
  role: { type: String, enum: ['admin', 'user', 'participant'], default: 'participant' },
  otpHash: String, otpExpires: Date, otpTries: { type: Number, default: 0 },
}, { timestamps: true }));

// Free area/space a customer lists for events. Admin approves it.
const Venue = model('Venue', new Schema({
  owner: ref('User'), name: String, city: String, address: String,
  capacity: Number,
  bookingAmount: Number, // full amount to book this area for an event
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
}, { timestamps: true }));

// Sponsor books a venue -> pays 50% of bookingAmount -> event confirmed
const Event = model('Event', new Schema({
  venue: ref('Venue'), organizer: ref('User'),
  title: String, description: String, date: Date,
  ticketPrice: Number, seats: Number, sold: { type: Number, default: 0 },
  sponsorAmount: Number,
  status: { type: String, enum: ['awaiting_payment', 'confirmed', 'cancelled'], default: 'awaiting_payment' },
}, { timestamps: true }));

const Payment = model('Payment', new Schema({
  user: ref('User'), event: ref('Event'),
  kind: { type: String, enum: ['sponsor', 'participant'] },
  amount: Number, txnId: String, status: { type: String, enum: ['success', 'failed'] },
  reason: String,
}, { timestamps: true }));

const Ticket = model('Ticket', new Schema({
  code: { type: String, unique: true },
  user: ref('User'), event: ref('Event'), payment: ref('Payment'),
  kind: { type: String, enum: ['sponsor', 'participant'] },
  amount: Number,
}, { timestamps: true }));

/* ---------- Fake payment gateway ---------- */
// Card ending 0000 => declined. Anything else => success.
async function fakeGateway({ amount, cardNumber }) {
  await new Promise((r) => setTimeout(r, 400)); // simulate latency
  const digits = String(cardNumber || '').replace(/\D/g, '');
  if (digits.length < 12) return { ok: false, reason: 'Invalid card number' };
  if (digits.endsWith('0000')) return { ok: false, reason: 'Card declined' };
  return { ok: true, txnId: 'TXN-' + crypto.randomBytes(6).toString('hex').toUpperCase() };
}

async function charge({ user, event, kind, amount, cardNumber }) {
  const res = await fakeGateway({ amount, cardNumber });
  const payment = await Payment.create({
    user, event, kind, amount, txnId: res.txnId || 'FAILED-' + Date.now(),
    status: res.ok ? 'success' : 'failed', reason: res.reason,
  });
  return { ok: res.ok, reason: res.reason, payment };
}

async function issueTicket({ user, event, payment, kind, amount }) {
  return Ticket.create({
    code: 'TKT-' + crypto.randomBytes(5).toString('hex').toUpperCase(),
    user, event, payment: payment._id, kind, amount,
  });
}

// Acknowledgment sent to sponsors and participants alike
async function acknowledgment(ticket) {
  const t = await Ticket.findById(ticket._id).populate('user', 'name email')
    .populate({ path: 'event', populate: { path: 'venue', select: 'name city address' } })
    .populate('payment', 'txnId amount status createdAt');
  const isSponsor = t.kind === 'sponsor';
  return {
    ticketCode: t.code,
    role: t.kind,
    issuedTo: t.user.name, email: t.user.email,
    event: t.event.title, date: t.event.date,
    venue: `${t.event.venue.name}, ${t.event.venue.city}`,
    amountPaid: t.amount, transactionId: t.payment.txnId,
    message: isSponsor
      ? `Thank you ${t.user.name}! Your 50% sponsor payment is received and "${t.event.title}" is confirmed. You are the organiser.`
      : `Thank you ${t.user.name}! Your seat for "${t.event.title}" is booked.`,
  };
}

/* ---------- Auth ---------- */
const wrap = (fn) => (req, res) => fn(req, res).catch((e) => res.status(e.status || 500).json({ error: e.message }));
const fail = (status, message) => Object.assign(new Error(message), { status });

const auth = (roles) => async (req, res, next) => {
  try {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    const { id, otp } = jwt.verify(token, JWT_SECRET);
    if (otp) throw 0; // password OK but code not yet entered: not a full login
    req.user = await User.findById(id);
    if (!req.user) throw 0;
    if (roles && !roles.includes(req.user.role)) return res.status(403).json({ error: 'Not allowed' });
    next();
  } catch { res.status(401).json({ error: 'Please log in' }); }
};
// Step 1 of 2FA: password was correct -> create a 6-digit code valid for 5 minutes
async function startOtp(u) {
  const code = String(crypto.randomInt(100000, 1000000));
  u.otpHash = await bcrypt.hash(code, 8); u.otpExpires = new Date(Date.now() + 5 * 60e3); u.otpTries = 0;
  await u.save();
  console.log(`[2FA] Code for ${u.email}: ${code}`); // in production, send by email/SMS instead
  return { twoFactor: true, tempToken: jwt.sign({ id: u._id, otp: true }, JWT_SECRET, { expiresIn: '5m' }), ...(SHOW_OTP ? { demoOtp: code } : {}) };
}
const sign = (u) => ({ token: jwt.sign({ id: u._id }, JWT_SECRET, { expiresIn: '7d' }), user: { id: u._id, name: u.name, email: u.email, role: u.role } });

/* ---------- Routes ---------- */
const app = express();
app.use(express.json());
app.use(express.static('public'));
app.use('/api', async (req, res, next) => {
  try { await init(); next(); } catch (e) { console.error(e.message); res.status(500).json({ error: 'Database connection failed' }); }
});

app.post('/api/register', wrap(async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) throw fail(400, 'Name, email and password are required');
  if (await User.findOne({ email })) throw fail(409, 'Email already registered');
  const role = ['user', 'participant'].includes(req.body.role) ? req.body.role : 'participant';
  const u = await User.create({ name, email, role, password: await bcrypt.hash(password, 10) });
  res.json(await startOtp(u));
}));

app.post('/api/login', wrap(async (req, res) => {
  const u = await User.findOne({ email: req.body.email });
  if (!u || !(await bcrypt.compare(req.body.password || '', u.password))) throw fail(401, 'Wrong email or password');
  res.json(await startOtp(u));
}));

// Step 2 of 2FA: check the code, then issue the real login token
app.post('/api/verify-otp', wrap(async (req, res) => {
  let id; try { ({ id } = jwt.verify(req.body.tempToken || '', JWT_SECRET)); } catch { throw fail(401, 'Code expired. Log in again'); }
  const u = await User.findById(id);
  if (!u || !u.otpHash || u.otpExpires < new Date()) throw fail(401, 'Code expired. Log in again');
  if (u.otpTries >= 5) throw fail(429, 'Too many wrong codes. Log in again');
  if (!(await bcrypt.compare(String(req.body.code || '').trim(), u.otpHash))) { u.otpTries += 1; await u.save(); throw fail(401, 'Wrong code'); }
  u.otpHash = undefined; u.otpExpires = undefined; await u.save();
  res.json(sign(u));
}));

// Venues (areas)
app.post('/api/venues', auth(['user', 'admin']), wrap(async (req, res) => {
  const { name, city, address, capacity, bookingAmount } = req.body;
  if (!name || !city || !(capacity > 0) || !(bookingAmount > 0)) throw fail(400, 'Name, city, capacity and booking amount are required');
  const v = await Venue.create({ owner: req.user._id, name, city, address, capacity, bookingAmount,
    status: req.user.role === 'admin' ? 'approved' : 'pending' });
  res.json(v);
}));

app.get('/api/venues', auth(['user', 'admin']), wrap(async (req, res) => {
  const q = req.user.role === 'admin' ? {} : { $or: [{ status: 'approved' }, { owner: req.user._id }] };
  res.json(await Venue.find(q).populate('owner', 'name').sort('-createdAt'));
}));

app.patch('/api/venues/:id/status', auth(['admin']), wrap(async (req, res) => {
  if (!['approved', 'rejected'].includes(req.body.status)) throw fail(400, 'Invalid status');
  res.json(await Venue.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true }));
}));

// Events: sponsor reserves an approved venue on a date
app.post('/api/events', auth(['user']), wrap(async (req, res) => {
  const { venueId, title, description, date, ticketPrice, seats } = req.body;
  const venue = await Venue.findById(venueId);
  if (!venue || venue.status !== 'approved') throw fail(400, 'Venue is not available');
  if (!title || !date || !(ticketPrice >= 0) || !(seats > 0)) throw fail(400, 'Title, date, ticket price and seats are required');
  if (seats > venue.capacity) throw fail(400, `Seats cannot exceed venue capacity (${venue.capacity})`);
  const day = new Date(date); const start = new Date(day.setHours(0, 0, 0, 0)); const end = new Date(start.getTime() + 864e5);
  const clash = await Event.findOne({ venue: venueId, status: { $ne: 'cancelled' }, date: { $gte: start, $lt: end } });
  if (clash) throw fail(409, 'This venue is already booked on that date');
  const ev = await Event.create({ venue: venueId, organizer: req.user._id, title, description, date,
    ticketPrice, seats, sponsorAmount: venue.bookingAmount * 0.5 });
  res.json(ev);
}));

app.get('/api/events', auth(), wrap(async (req, res) => {
  res.json(await Event.find({ status: 'confirmed' }).populate('venue', 'name city').populate('organizer', 'name').sort('date'));
}));

app.get('/api/events/mine', auth(), wrap(async (req, res) => {
  res.json(await Event.find({ organizer: req.user._id }).populate('venue', 'name city bookingAmount').sort('-createdAt'));
}));

// Sponsor pays 50% -> event confirmed
app.post('/api/events/:id/sponsor-pay', auth(), wrap(async (req, res) => {
  const ev = await Event.findById(req.params.id);
  if (!ev || String(ev.organizer) !== String(req.user._id)) throw fail(404, 'Event not found');
  if (ev.status !== 'awaiting_payment') throw fail(400, 'Event is already paid');
  const r = await charge({ user: req.user._id, event: ev._id, kind: 'sponsor', amount: ev.sponsorAmount, cardNumber: req.body.cardNumber });
  if (!r.ok) throw fail(402, r.reason);
  ev.status = 'confirmed'; await ev.save();
  const ticket = await issueTicket({ user: req.user._id, event: ev._id, payment: r.payment, kind: 'sponsor', amount: ev.sponsorAmount });
  res.json(await acknowledgment(ticket));
}));

// Participant pays the full ticket price
app.post('/api/events/:id/join', auth(['participant']), wrap(async (req, res) => {
  const ev = await Event.findById(req.params.id);
  if (!ev || ev.status !== 'confirmed') throw fail(404, 'Event is not open for booking');
  if (ev.sold >= ev.seats) throw fail(400, 'Sold out');
  if (await Ticket.findOne({ event: ev._id, user: req.user._id, kind: 'participant' })) throw fail(409, 'You already have a ticket for this event');
  // reserve the seat atomically
  const held = await Event.findOneAndUpdate({ _id: ev._id, $expr: { $lt: ['$sold', '$seats'] } }, { $inc: { sold: 1 } });
  if (!held) throw fail(400, 'Sold out');
  const r = await charge({ user: req.user._id, event: ev._id, kind: 'participant', amount: ev.ticketPrice, cardNumber: req.body.cardNumber });
  if (!r.ok) { await Event.updateOne({ _id: ev._id }, { $inc: { sold: -1 } }); throw fail(402, r.reason); }
  const ticket = await issueTicket({ user: req.user._id, event: ev._id, payment: r.payment, kind: 'participant', amount: ev.ticketPrice });
  res.json(await acknowledgment(ticket));
}));

app.get('/api/tickets/mine', auth(), wrap(async (req, res) => {
  const tickets = await Ticket.find({ user: req.user._id }).sort('-createdAt');
  res.json(await Promise.all(tickets.map(acknowledgment)));
}));

// Admin overview
app.get('/api/admin/stats', auth(['admin']), wrap(async (req, res) => {
  const [users, venues, events, tickets, rev] = await Promise.all([
    User.countDocuments(), Venue.countDocuments(), Event.countDocuments({ status: 'confirmed' }), Ticket.countDocuments(),
    Payment.aggregate([{ $match: { status: 'success' } }, { $group: { _id: '$kind', total: { $sum: '$amount' } } }]),
  ]);
  res.json({ users, venues, events, tickets, revenue: Object.fromEntries(rev.map((r) => [r._id, r.total])) });
}));

// Admin portal: every event (any status) and every user
app.get('/api/admin/events', auth(['admin']), wrap(async (req, res) => {
  res.json(await Event.find().populate('venue', 'name city').populate('organizer', 'name email').sort('-createdAt'));
}));
app.get('/api/admin/users', auth(['admin']), wrap(async (req, res) => {
  res.json(await User.find().select('name email role createdAt').sort('-createdAt'));
}));

// Demo data so every section has something to show
async function seedDemo() {
  if (await User.findOne({ email: 'organizer@demo.com' })) return;
  const hash = await bcrypt.hash('demo123', 10);
  const org = await User.create({ name: 'Demo Organiser', email: 'organizer@demo.com', password: hash, role: 'user' });
  const ppl = await User.create({ name: 'Demo Participant', email: 'participant@demo.com', password: hash, role: 'participant' });
  const V = await Venue.insertMany([
    { owner: org._id, name: 'Riverside Lawn', city: 'Ludhiana', address: 'Ferozepur Road', capacity: 500, bookingAmount: 40000, status: 'approved' },
    { owner: org._id, name: 'Old Town Hall', city: 'Chandigarh', address: 'Sector 17', capacity: 300, bookingAmount: 60000, status: 'approved' },
    { owner: org._id, name: 'Sunset Rooftop', city: 'Amritsar', address: 'Mall Road', capacity: 120, bookingAmount: 25000, status: 'pending' },
  ]);
  const day = (n) => new Date(Date.now() + n * 864e5);
  const mk = (v, title, description, d, ticketPrice, seats, sponsorAmount, status = 'confirmed', sold = 0) =>
    ({ venue: V[v]._id, organizer: org._id, title, description, date: day(d), ticketPrice, seats, sponsorAmount, status, sold });
  const E = await Event.insertMany([
    mk(0, 'Punjab Food Festival', 'Street food, live music and family stalls.', 10, 499, 300, 20000, 'confirmed', 1),
    mk(1, 'Startup Pitch Night', 'Ten founders pitch to local investors.', 18, 799, 150, 30000),
    mk(0, 'Indie Music Evening', 'Three bands, open-air stage.', 25, 299, 400, 20000),
    mk(1, 'Photography Walk & Expo', 'Morning walk, afternoon exhibition.', 40, 199, 80, 30000, 'awaiting_payment'),
  ]);
  const sales = [[E[0], org, 'sponsor'], [E[0], ppl, 'participant'], [E[1], org, 'sponsor'], [E[2], org, 'sponsor']];
  for (const [ev, who, kind] of sales) {
    const amount = kind === 'sponsor' ? ev.sponsorAmount : ev.ticketPrice;
    const p = await Payment.create({ user: who._id, event: ev._id, kind, amount, txnId: 'TXN-SEED' + crypto.randomBytes(3).toString('hex').toUpperCase(), status: 'success' });
    await issueTicket({ user: who._id, event: ev._id, payment: p, kind, amount });
  }
  console.log('Seeded demo: organizer@demo.com / demo123, participant@demo.com / demo123');
}

/* ---------- Start ---------- */
// Connect once and reuse the connection (works locally and on Vercel serverless)
let ready;
function init() {
  ready ||= mongoose.connect(MONGO_URI).then(async () => {
    await User.updateMany({ role: 'customer' }, { role: 'user' }); // older accounts from the first version
    if (!(await User.findOne({ role: 'admin' }))) {
      await User.create({ name: 'Admin', email: 'admin@demo.com', password: await bcrypt.hash('admin123', 10), role: 'admin' });
      console.log('Seeded admin: admin@demo.com / admin123');
    }
    await seedDemo();
  }).catch((e) => { ready = null; throw e; });
  return ready;
}

module.exports = app; // Vercel uses this export

if (require.main === module) { // local: node server.js
  init().then(() => app.listen(PORT, () => console.log(`http://localhost:${PORT}`)))
    .catch((e) => { console.error('MongoDB connection failed:', e.message); process.exit(1); });
}
