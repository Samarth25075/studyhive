const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Redis = require('ioredis');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const cloudinary = require('cloudinary').v2;
const sgMail = require('@sendgrid/mail');
require('dotenv').config();

// Initialize Express
const app = express();
const server = http.createServer(app);

// ============================================
// CONFIGURATION
// ============================================

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/studyhive', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ MongoDB connected'))
.catch(err => console.error('❌ MongoDB error:', err));

// Redis Connection (for presence and caching)
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

redis.on('connect', () => console.log('✅ Redis connected'));
redis.on('error', (err) => console.error('❌ Redis error:', err));

// Cloudinary Config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// SendGrid Config
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// ============================================
// MIDDLEWARE
// ============================================

app.use(helmet());
app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests, please try again later.'
});
app.use('/api/', limiter);

// ============================================
// DATABASE MODELS
// ============================================

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  avatar: { type: String, default: '' },
  role: { type: String, enum: ['user', 'mentor', 'admin'], default: 'user' },
  xp: { type: Number, default: 0 },
  level: { type: Number, default: 1 },
  isOnline: { type: Boolean, default: false },
  lastSeen: { type: Date, default: Date.now },
  premium: {
    isPremium: { type: Boolean, default: false },
    plan: { type: String, enum: ['free', 'plus', 'pro'], default: 'free' },
    expiresAt: { type: Date },
    stripeCustomerId: { type: String }
  },
  stats: {
    messagesSent: { type: Number, default: 0 },
    solutionsAccepted: { type: Number, default: 0 },
    studyHours: { type: Number, default: 0 }
  },
  createdAt: { type: Date, default: Date.now }
});

// Channel Schema
const channelSchema = new mongoose.Schema({
  name: { type: String, required: true },
  type: { type: String, enum: ['subject', 'study-group', 'dm', 'voice'], default: 'subject' },
  description: { type: String },
  icon: { type: String },
  isPrivate: { type: Boolean, default: false },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  moderators: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  settings: {
    slowMode: { type: Boolean, default: false },
    slowModeDelay: { type: Number, default: 0 },
    allowFiles: { type: Boolean, default: true }
  },
  createdAt: { type: Date, default: Date.now }
});

// Message Schema
const messageSchema = new mongoose.Schema({
  channelId: { type: mongoose.Schema.Types.ObjectId, ref: 'Channel', required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: true },
  type: { 
    type: String, 
    enum: ['text', 'code', 'latex', 'image', 'file', 'system'], 
    default: 'text' 
  },
  codeLanguage: { type: String },
  attachments: [{
    url: String,
    type: String,
    name: String,
    size: Number
  }],
  reactions: [{
    emoji: String,
    users: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
  }],
  isSolution: { type: Boolean, default: false },
  parentMessage: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' },
  threadCount: { type: Number, default: 0 },
  mentions: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  edited: { type: Boolean, default: false },
  editedAt: { type: Date },
  deleted: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

// Voice Room Schema
const voiceRoomSchema = new mongoose.Schema({
  channelId: { type: mongoose.Schema.Types.ObjectId, ref: 'Channel' },
  name: { type: String, required: true },
  participants: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    joinedAt: { type: Date, default: Date.now },
    isMuted: { type: Boolean, default: false },
    isDeafened: { type: Boolean, default: false },
    isSpeaking: { type: Boolean, default: false }
  }],
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

// Notification Schema
const notificationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { 
    type: String, 
    enum: ['message', 'mention', 'reaction', 'solution', 'join', 'premium'] 
  },
  title: String,
  content: String,
  data: mongoose.Schema.Types.Mixed,
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

// Create models
const User = mongoose.model('User', userSchema);
const Channel = mongoose.model('Channel', channelSchema);
const Message = mongoose.model('Message', messageSchema);
const VoiceRoom = mongoose.model('VoiceRoom', voiceRoomSchema);
const Notification = mongoose.model('Notification', notificationSchema);

// ============================================
// AUTH MIDDLEWARE
// ============================================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'secret', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

const authenticateSocket = (socket, next) => {
  const token = socket.handshake.auth.token;
  
  if (!token) {
    return next(new Error('Authentication required'));
  }

  jwt.verify(token, process.env.JWT_SECRET || 'secret', async (err, decoded) => {
    if (err) {
      return next(new Error('Invalid token'));
    }

    try {
      const user = await User.findById(decoded.userId);
      if (!user) {
        return next(new Error('User not found'));
      }

      socket.user = {
        id: user._id,
        username: user.username,
        role: user.role,
        premium: user.premium
      };

      // Update user online status
      await User.findByIdAndUpdate(user._id, { 
        isOnline: true, 
        lastSeen: new Date() 
      });

      // Store in Redis
      await redis.set(`user:${user._id}:socket`, socket.id);
      await redis.sadd('online_users', user._id.toString());

      next();
    } catch (err) {
      next(new Error('Database error'));
    }
  });
};

// ============================================
// API ROUTES
// ============================================

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });
    
    if (existingUser) {
      return res.status(400).json({ 
        error: 'User with this email or username already exists' 
      });
    }

    // Hash password
    const bcrypt = require('bcryptjs');
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      username,
      email,
      password: hashedPassword,
      avatar: `https://ui-avatars.com/api/?name=${username}&background=random`
    });

    await user.save();

    // Generate token
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '7d' }
    );

    // Send welcome email (async)
    try {
      await sgMail.send({
        to: email,
        from: 'welcome@studyhive.app',
        subject: 'Welcome to StudyHive!',
        html: `
          <h1>Welcome to StudyHive, ${username}! 🎓</h1>
          <p>Your study journey begins now. Join channels, ask questions, and help others.</p>
          <a href="${process.env.CLIENT_URL}/channels">Start Studying →</a>
        `
      });
    } catch (emailErr) {
      console.error('Email send failed:', emailErr);
    }

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        avatar: user.avatar,
        role: user.role,
        premium: user.premium
      }
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Check password
    const bcrypt = require('bcryptjs');
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generate token
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '7d' }
    );

    // Update last seen
    user.lastSeen = new Date();
    await user.save();

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        avatar: user.avatar,
        role: user.role,
        xp: user.xp,
        level: user.level,
        premium: user.premium
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Channel Routes
app.get('/api/channels', authenticateToken, async (req, res) => {
  try {
    const channels = await Channel.find({
      $or: [
        { isPrivate: false },
        { members: req.user.userId }
      ]
    })
    .populate('members', 'username avatar isOnline')
    .populate('moderators', 'username avatar')
    .sort({ name: 1 });

    // Get unread counts from Redis
    const channelsWithUnread = await Promise.all(
      channels.map(async (channel) => {
        const lastRead = await redis.get(
          `user:${req.user.userId}:channel:${channel._id}:lastRead`
        );
        
        const unreadCount = lastRead 
          ? await Message.countDocuments({
              channelId: channel._id,
              createdAt: { $gt: new Date(parseInt(lastRead)) }
            })
          : 0;

        return {
          ...channel.toObject(),
          unreadCount
        };
      })
    );

    res.json(channelsWithUnread);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/channels', authenticateToken, async (req, res) => {
  try {
    const { name, type, description, isPrivate } = req.body;

    // Check premium limits for free users
    const user = await User.findById(req.user.userId);
    if (!user.premium.isPremium) {
      const userChannels = await Channel.countDocuments({
        'members': req.user.userId
      });
      
      if (userChannels >= 10) {
        return res.status(403).json({ 
          error: 'Free users can join max 10 channels. Upgrade to premium!'
        });
      }
    }

    const channel = new Channel({
      name,
      type,
      description,
      isPrivate,
      members: [req.user.userId],
      moderators: [req.user.userId]
    });

    await channel.save();
    
    // Populate member info
    await channel.populate('members', 'username avatar isOnline');
    await channel.populate('moderators', 'username avatar');

    // Notify via socket
    io.emit('channel:created', channel);

    res.status(201).json(channel);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Message Routes
app.get('/api/messages/:channelId', authenticateToken, async (req, res) => {
  try {
    const { channelId } = req.params;
    const { limit = 50, before } = req.query;

    // Check if user is member of channel
    const channel = await Channel.findOne({
      _id: channelId,
      $or: [
        { isPrivate: false },
        { members: req.user.userId }
      ]
    });

    if (!channel) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Build query
    const query = { channelId, deleted: false };
    if (before) {
      query.createdAt = { $lt: new Date(before) };
    }

    const messages = await Message.find(query)
      .populate('userId', 'username avatar role isOnline')
      .populate('mentions', 'username')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit));

    // Update last read in Redis
    if (messages.length > 0) {
      await redis.set(
        `user:${req.user.userId}:channel:${channelId}:lastRead`,
        Date.now().toString()
      );
    }

    res.json(messages.reverse());
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/messages', authenticateToken, async (req, res) => {
  try {
    const { channelId, content, type, codeLanguage, parentMessage } = req.body;

    // Check if user is member
    const channel = await Channel.findOne({
      _id: channelId,
      members: req.user.userId
    });

    if (!channel) {
      return res.status(403).json({ error: 'Not a member of this channel' });
    }

    // Check slow mode
    if (channel.settings.slowMode) {
      const lastMessage = await Message.findOne({
        channelId,
        userId: req.user.userId
      }).sort({ createdAt: -1 });

      if (lastMessage) {
        const timeDiff = Date.now() - lastMessage.createdAt;
        if (timeDiff < channel.settings.slowModeDelay * 1000) {
          return res.status(429).json({ 
            error: `Slow mode enabled. Wait ${channel.settings.slowModeDelay} seconds` 
          });
        }
      }
    }

    // Extract mentions
    const mentionRegex = /@(\w+)/g;
    const mentions = [];
    let match;
    while ((match = mentionRegex.exec(content)) !== null) {
      const mentionedUser = await User.findOne({ username: match[1] });
      if (mentionedUser) {
        mentions.push(mentionedUser._id);
      }
    }

    const message = new Message({
      channelId,
      userId: req.user.userId,
      content,
      type,
      codeLanguage,
      parentMessage,
      mentions
    });

    await message.save();
    await message.populate('userId', 'username avatar role');
    
    if (mentions.length > 0) {
      await message.populate('mentions', 'username');
      
      // Create notifications for mentions
      const notifications = mentions.map(userId => ({
        userId,
        type: 'mention',
        title: 'You were mentioned',
        content: `${message.userId.username} mentioned you in #${channel.name}`,
        data: {
          channelId,
          messageId: message._id,
          username: message.userId.username
        }
      }));
      
      await Notification.insertMany(notifications);
      
      // Emit socket events for mentions
      mentions.forEach(userId => {
        io.to(`user:${userId}`).emit('notification:new', {
          type: 'mention',
          from: message.userId.username,
          channel: channel.name,
          messageId: message._id
        });
      });
    }

    // Update thread count if it's a reply
    if (parentMessage) {
      await Message.findByIdAndUpdate(parentMessage, {
        $inc: { threadCount: 1 }
      });
    }

    // Update user stats
    await User.findByIdAndUpdate(req.user.userId, {
      $inc: { 'stats.messagesSent': 1, xp: 10 }
    });

    // Emit to channel
    io.to(`channel:${channelId}`).emit('message:new', message);

    res.status(201).json(message);
  } catch (err) {
    console.error('Message error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/messages/:messageId/reaction', authenticateToken, async (req, res) => {
  try {
    const { messageId } = req.params;
    const { emoji } = req.body;

    const message = await Message.findById(messageId);
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

    // Find reaction
    const reactionIndex = message.reactions.findIndex(r => r.emoji === emoji);

    if (reactionIndex === -1) {
      // Add new reaction
      message.reactions.push({
        emoji,
        users: [req.user.userId]
      });
    } else {
      const reaction = message.reactions[reactionIndex];
      const userReacted = reaction.users.includes(req.user.userId);

      if (userReacted) {
        // Remove reaction
        reaction.users = reaction.users.filter(
          id => id.toString() !== req.user.userId
        );
        if (reaction.users.length === 0) {
          message.reactions.splice(reactionIndex, 1);
        }
      } else {
        // Add user to reaction
        reaction.users.push(req.user.userId);
      }
    }

    await message.save();

    // Emit update
    io.to(`channel:${message.channelId}`).emit('message:reaction', {
      messageId,
      reactions: message.reactions
    });

    res.json(message.reactions);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/messages/:messageId/solution', authenticateToken, async (req, res) => {
  try {
    const { messageId } = req.params;

    const message = await Message.findById(messageId)
      .populate('channelId');

    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

    // Check if user is moderator
    const channel = await Channel.findOne({
      _id: message.channelId,
      moderators: req.user.userId
    });

    if (!channel && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Only moderators can mark solutions' });
    }

    // Remove previous solution
    await Message.updateMany(
      { 
        channelId: message.channelId,
        parentMessage: message.parentMessage 
      },
      { isSolution: false }
    );

    // Mark this as solution
    message.isSolution = true;
    await message.save();

    // Award XP to solution author
    await User.findByIdAndUpdate(message.userId, {
      $inc: { 'stats.solutionsAccepted': 1, xp: 50 }
    });

    // Notify
    io.to(`channel:${message.channelId}`).emit('message:solution', {
      messageId,
      userId: message.userId
    });

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// File Upload
app.post('/api/upload', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    // Upload to Cloudinary
    const result = await cloudinary.uploader.upload(req.file.path, {
      resource_type: 'auto',
      folder: 'studyhive'
    });

    res.json({
      url: result.secure_url,
      type: result.resource_type,
      name: req.file.originalname,
      size: req.file.size
    });
  } catch (err) {
    res.status(500).json({ error: 'Upload failed' });
  }
});

// Premium Routes
app.post('/api/premium/create-checkout', authenticateToken, async (req, res) => {
  try {
    const { plan } = req.body; // 'plus' or 'pro'
    
    const prices = {
      plus: 499, // $4.99
      pro: 999   // $9.99
    };

    // In production, use Stripe
    // For now, simulate payment
    
    const user = await User.findById(req.user.userId);
    user.premium.isPremium = true;
    user.premium.plan = plan;
    user.premium.expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
    await user.save();

    res.json({ 
      success: true, 
      message: 'Premium activated',
      plan
    });
  } catch (err) {
    res.status(500).json({ error: 'Payment failed' });
  }
});

// ============================================
// SOCKET.IO HANDLERS
// ============================================

const io = socketIo(server, {
  cors: {
    origin: process.env.CLIENT_URL || 'http://localhost:3000',
    credentials: true
  }
});

io.use(authenticateSocket);

io.on('connection', (socket) => {
  console.log(`🔌 User connected: ${socket.user.username}`);

  // Join user's personal room
  socket.join(`user:${socket.user.id}`);

  // Broadcast online status
  socket.broadcast.emit('user:online', {
    userId: socket.user.id,
    username: socket.user.username
  });

  // Join channels
  socket.on('channel:join', async (channelId) => {
    try {
      // Check if user is member
      const channel = await Channel.findOne({
        _id: channelId,
        members: socket.user.id
      });

      if (channel) {
        socket.join(`channel:${channelId}`);
        socket.to(`channel:${channelId}`).emit('user:joined', {
          userId: socket.user.id,
          username: socket.user.username
        });

        // Add to channel presence in Redis
        await redis.sadd(`channel:${channelId}:users`, socket.user.id);
      }
    } catch (err) {
      console.error('Channel join error:', err);
    }
  });

  // Leave channel
  socket.on('channel:leave', (channelId) => {
    socket.leave(`channel:${channelId}`);
    socket.to(`channel:${channelId}`).emit('user:left', {
      userId: socket.user.id,
      username: socket.user.username
    });
    redis.srem(`channel:${channelId}:users`, socket.user.id);
  });

  // Typing indicator
  socket.on('typing:start', ({ channelId }) => {
    socket.to(`channel:${channelId}`).emit('typing:start', {
      userId: socket.user.id,
      username: socket.user.username
    });
  });

  socket.on('typing:stop', ({ channelId }) => {
    socket.to(`channel:${channelId}`).emit('typing:stop', {
      userId: socket.user.id
    });
  });

  // Message read receipt
  socket.on('message:read', async ({ channelId, messageId }) => {
    await redis.set(
      `user:${socket.user.id}:channel:${channelId}:lastRead`,
      Date.now().toString()
    );
    
    socket.to(`channel:${channelId}`).emit('message:read', {
      userId: socket.user.id,
      messageId
    });
  });

  // Voice/Video signaling
  socket.on('voice:join', async ({ roomId }) => {
    try {
      let voiceRoom = await VoiceRoom.findOne({ channelId: roomId });
      
      if (!voiceRoom) {
        voiceRoom = new VoiceRoom({
          channelId: roomId,
          name: 'Voice Channel',
          participants: []
        });
      }

      // Add participant
      voiceRoom.participants.push({
        userId: socket.user.id,
        joinedAt: new Date()
      });
      await voiceRoom.save();

      socket.join(`voice:${roomId}`);
      
      // Notify others
      socket.to(`voice:${roomId}`).emit('voice:participant-joined', {
        userId: socket.user.id,
        username: socket.user.username
      });

      // Send current participants to new user
      const participants = await Promise.all(
        voiceRoom.participants.map(async (p) => {
          const user = await User.findById(p.userId);
          return {
            userId: p.userId,
            username: user.username,
            avatar: user.avatar,
            isMuted: p.isMuted,
            isSpeaking: p.isSpeaking
          };
        })
      );

      socket.emit('voice:participants', participants);
    } catch (err) {
      console.error('Voice join error:', err);
    }
  });

  socket.on('voice:leave', async ({ roomId }) => {
    await VoiceRoom.updateOne(
      { channelId: roomId },
      { $pull: { participants: { userId: socket.user.id } } }
    );

    socket.leave(`voice:${roomId}`);
    socket.to(`voice:${roomId}`).emit('voice:participant-left', {
      userId: socket.user.id
    });
  });

  socket.on('voice:signal', ({ to, signal }) => {
    io.to(`user:${to}`).emit('voice:signal', {
      from: socket.user.id,
      signal
    });
  });

  // Video signaling
  socket.on('video:offer', ({ to, offer }) => {
    io.to(`user:${to}`).emit('video:offer', {
      from: socket.user.id,
      offer
    });
  });

  socket.on('video:answer', ({ to, answer }) => {
    io.to(`user:${to}`).emit('video:answer', {
      from: socket.user.id,
      answer
    });
  });

  socket.on('video:ice-candidate', ({ to, candidate }) => {
    io.to(`user:${to}`).emit('video:ice-candidate', {
      from: socket.user.id,
      candidate
    });
  });

  // Disconnect
  socket.on('disconnect', async () => {
    console.log(`🔌 User disconnected: ${socket.user.username}`);

    // Update user status
    await User.findByIdAndUpdate(socket.user.id, {
      isOnline: false,
      lastSeen: new Date()
    });

    // Remove from Redis
    await redis.del(`user:${socket.user.id}:socket`);
    await redis.srem('online_users', socket.user.id);

    // Remove from voice rooms
    await VoiceRoom.updateMany(
      { 'participants.userId': socket.user.id },
      { $pull: { participants: { userId: socket.user.id } } }
    );

    // Broadcast offline status
    socket.broadcast.emit('user:offline', {
      userId: socket.user.id,
      username: socket.user.username
    });
  });
});

// ============================================
// START SERVER
// ============================================

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});