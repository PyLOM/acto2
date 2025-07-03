const express = require("express")
const http = require("http")
const socketIo = require("socket.io")
const cors = require("cors")
const mongoose = require("mongoose")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const multer = require("multer")
const path = require("path")
const fs = require("fs")

const app = express()
const server = http.createServer(app)

// Socket.IO настройка
const io = socketIo(server, {
  cors: {
    origin:
      process.env.NODE_ENV === "production"
        ? ["https://actogram.vercel.app", "https://actogram.onrender.com"]
        : ["http://localhost:3000", "http://127.0.0.1:3000"],
    methods: ["GET", "POST"],
    credentials: true,
  },
  maxHttpBufferSize: 100 * 1024 * 1024, // 100MB для файлов
})

// Middleware
app.use(
  cors({
    origin:
      process.env.NODE_ENV === "production"
        ? ["https://actogram.vercel.app", "https://actogram.onrender.com"]
        : ["http://localhost:3000", "http://127.0.0.1:3000"],
    credentials: true,
  }),
)
app.use(express.json({ limit: "100mb" }))
app.use(express.urlencoded({ extended: true, limit: "100mb" }))

// Создание папки для загрузок
const uploadsDir = path.join(__dirname, "uploads")
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true })
}

// Статические файлы
app.use("/uploads", express.static(uploadsDir))

// Настройка Multer для загрузки файлов
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir)
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9)
    cb(null, uniqueSuffix + path.extname(file.originalname))
  },
})

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 100 * 1024 * 1024, // 100MB
  },
  fileFilter: (req, file, cb) => {
    // Разрешенные типы файлов
    const allowedTypes = /jpeg|jpg|png|gif|mp4|mov|avi|pdf|doc|docx|txt|mp3|wav|ogg/
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase())
    const mimetype = allowedTypes.test(file.mimetype)

    if (mimetype && extname) {
      return cb(null, true)
    } else {
      cb(new Error("Неподдерживаемый тип файла"))
    }
  },
})

// MongoDB подключение с предоставленным URI
const MONGODB_URI =
  process.env.MONGODB_URI ||
  "mongodb+srv://r37749651:dVILr5pebUczVCUX@actogram.c7d7pih.mongodb.net/?retryWrites=true&w=majority&appName=Actogram"

mongoose
  .connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("✅ MongoDB подключена успешно")
    console.log("🗄️ База данных: Actogram")
  })
  .catch((err) => {
    console.error("❌ Ошибка подключения к MongoDB:", err)
    process.exit(1)
  })

// Обработка событий подключения к MongoDB
mongoose.connection.on("connected", () => {
  console.log("🔗 Mongoose подключен к MongoDB")
})

mongoose.connection.on("error", (err) => {
  console.error("❌ Ошибка Mongoose:", err)
})

mongoose.connection.on("disconnected", () => {
  console.log("🔌 Mongoose отключен от MongoDB")
})

// Схемы MongoDB
const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
      minlength: 3,
      maxlength: 30,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
    },
    password: {
      type: String,
      required: true,
      minlength: 6,
    },
    displayName: {
      type: String,
      required: true,
      trim: true,
      minlength: 2,
      maxlength: 50,
    },
    avatar: {
      type: String,
      default: "😊",
    },
    bio: {
      type: String,
      default: "Привет! Я использую ACTO Messenger",
      maxlength: 200,
    },
    isOnline: {
      type: Boolean,
      default: false,
    },
    lastSeen: {
      type: Date,
      default: Date.now,
    },
    socketId: String,
    settings: {
      notifications: { type: Boolean, default: true },
      sounds: { type: Boolean, default: true },
      theme: { type: String, enum: ["dark", "light"], default: "light" },
      privacy: {
        lastSeen: { type: String, enum: ["everyone", "contacts", "nobody"], default: "everyone" },
        profilePhoto: { type: String, enum: ["everyone", "contacts", "nobody"], default: "everyone" },
        readReceipts: { type: Boolean, default: true },
      },
    },
    // Дополнительные поля для безопасности
    emailVerified: { type: Boolean, default: false },
    phoneNumber: String,
    twoFactorEnabled: { type: Boolean, default: false },
    loginAttempts: { type: Number, default: 0 },
    lockUntil: Date,
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  },
)

// Индексы для оптимизации поиска
userSchema.index({ username: 1 })
userSchema.index({ email: 1 })
userSchema.index({ displayName: "text" })
userSchema.index({ isOnline: 1 })

// Виртуальное поле для проверки блокировки аккаунта
userSchema.virtual("isLocked").get(function () {
  return !!(this.lockUntil && this.lockUntil > Date.now())
})

const chatSchema = new mongoose.Schema(
  {
    type: {
      type: String,
      enum: ["private", "group", "channel"],
      required: true,
    },
    name: {
      type: String,
      trim: true,
      maxlength: 100,
    },
    description: {
      type: String,
      maxlength: 500,
    },
    avatar: String,
    participants: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true,
      },
    ],
    admins: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
    ],
    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
    lastMessage: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Message",
    },
    settings: {
      allowMessages: { type: Boolean, default: true },
      allowMedia: { type: Boolean, default: true },
      muteNotifications: { type: Boolean, default: false },
    },
    // Дополнительные поля
    isArchived: { type: Boolean, default: false },
    isPinned: { type: Boolean, default: false },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  },
)

// Индексы для чатов
chatSchema.index({ participants: 1 })
chatSchema.index({ type: 1 })
chatSchema.index({ updatedAt: -1 })

const messageSchema = new mongoose.Schema(
  {
    chatId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Chat",
      required: true,
    },
    senderId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    content: {
      type: String,
      maxlength: 4000,
    },
    type: {
      type: String,
      enum: ["text", "image", "video", "audio", "file", "sticker", "system", "location"],
      default: "text",
    },
    fileUrl: String,
    fileName: String,
    fileSize: Number,
    fileMimeType: String,
    replyTo: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Message",
    },
    edited: {
      type: Boolean,
      default: false,
    },
    editedAt: Date,
    readBy: [
      {
        userId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User",
        },
        readAt: {
          type: Date,
          default: Date.now,
        },
      },
    ],
    // Дополнительные поля
    isDeleted: { type: Boolean, default: false },
    deletedAt: Date,
    reactions: [
      {
        userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
        emoji: String,
        createdAt: { type: Date, default: Date.now },
      },
    ],
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  },
)

// Индексы для сообщений
messageSchema.index({ chatId: 1, createdAt: -1 })
messageSchema.index({ senderId: 1 })
messageSchema.index({ "readBy.userId": 1 })

// Модели
const User = mongoose.model("User", userSchema)
const Chat = mongoose.model("Chat", chatSchema)
const Message = mongoose.model("Message", messageSchema)

// JWT секретный ключ
const JWT_SECRET = process.env.JWT_SECRET || "actogram_super_secret_key_2024"

// JWT middleware с улучшенной безопасностью
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers["authorization"]
    const token = authHeader && authHeader.split(" ")[1]

    if (!token) {
      return res.status(401).json({
        success: false,
        error: "Токен доступа не предоставлен",
      })
    }

    const decoded = jwt.verify(token, JWT_SECRET)

    // Проверяем существование пользователя
    const user = await User.findById(decoded.userId).select("-password")
    if (!user) {
      return res.status(401).json({
        success: false,
        error: "Пользователь не найден",
      })
    }

    // Проверяем блокировку аккаунта
    if (user.isLocked) {
      return res.status(423).json({
        success: false,
        error: "Аккаунт временно заблокирован",
      })
    }

    req.user = { userId: user._id, username: user.username }
    next()
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        success: false,
        error: "Токен истек",
      })
    }
    return res.status(403).json({
      success: false,
      error: "Недействительный токен",
    })
  }
}

// Стикеры
const STICKERS = [
  { id: 1, emoji: "😀", category: "happy" },
  { id: 2, emoji: "😂", category: "happy" },
  { id: 3, emoji: "🥰", category: "love" },
  { id: 4, emoji: "😍", category: "love" },
  { id: 5, emoji: "🤩", category: "happy" },
  { id: 6, emoji: "😎", category: "cool" },
  { id: 7, emoji: "🤔", category: "thinking" },
  { id: 8, emoji: "😴", category: "tired" },
  { id: 9, emoji: "🥳", category: "party" },
  { id: 10, emoji: "😭", category: "sad" },
  { id: 11, emoji: "😡", category: "angry" },
  { id: 12, emoji: "🤯", category: "shocked" },
  { id: 13, emoji: "👍", category: "gestures" },
  { id: 14, emoji: "👎", category: "gestures" },
  { id: 15, emoji: "👌", category: "gestures" },
  { id: 16, emoji: "✌️", category: "gestures" },
  { id: 17, emoji: "🤝", category: "gestures" },
  { id: 18, emoji: "👏", category: "gestures" },
  { id: 19, emoji: "🙏", category: "gestures" },
  { id: 20, emoji: "💪", category: "gestures" },
  { id: 21, emoji: "❤️", category: "hearts" },
  { id: 22, emoji: "💙", category: "hearts" },
  { id: 23, emoji: "💚", category: "hearts" },
  { id: 24, emoji: "💛", category: "hearts" },
  { id: 25, emoji: "🧡", category: "hearts" },
  { id: 26, emoji: "💜", category: "hearts" },
  { id: 27, emoji: "🖤", category: "hearts" },
  { id: 28, emoji: "🤍", category: "hearts" },
  { id: 29, emoji: "💔", category: "hearts" },
  { id: 30, emoji: "💕", category: "hearts" },
]

// API Routes

// Главная страница
app.get("/", (req, res) => {
  res.json({
    name: "ACTO Messenger API",
    version: "2.0.0",
    description: "Modern Real-time Messaging Platform",
    status: "running",
    database: "MongoDB Atlas",
    port: process.env.PORT || 3000,
    endpoints: {
      auth: "/api/auth/*",
      chats: "/api/chats/*",
      messages: "/api/messages/*",
      users: "/api/users/*",
      upload: "/api/upload",
      stickers: "/api/stickers",
    },
    features: [
      "Real-time messaging",
      "File uploads",
      "User authentication",
      "Group chats",
      "Message reactions",
      "Read receipts",
      "Online status",
      "Search functionality",
    ],
  })
})

// Регистрация с улучшенной валидацией
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, email, password, displayName, avatar } = req.body

    // Детальная валидация
    if (!username || username.length < 3 || username.length > 30) {
      return res.status(400).json({
        success: false,
        error: "Имя пользователя должно содержать от 3 до 30 символов",
      })
    }

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({
        success: false,
        error: "Введите корректный email адрес",
      })
    }

    if (!password || password.length < 6) {
      return res.status(400).json({
        success: false,
        error: "Пароль должен содержать минимум 6 символов",
      })
    }

    if (!displayName || displayName.length < 2 || displayName.length > 50) {
      return res.status(400).json({
        success: false,
        error: "Отображаемое имя должно содержать от 2 до 50 символов",
      })
    }

    // Очистка имени пользователя
    const cleanUsername = username.replace(/[@\s]/g, "").toLowerCase()

    // Проверка существования пользователя
    const existingUser = await User.findOne({
      $or: [{ username: cleanUsername }, { email: email.toLowerCase() }],
    })

    if (existingUser) {
      if (existingUser.username === cleanUsername) {
        return res.status(400).json({
          success: false,
          error: "Пользователь с таким именем уже существует",
        })
      } else {
        return res.status(400).json({
          success: false,
          error: "Пользователь с таким email уже существует",
        })
      }
    }

    // Хеширование пароля
    const saltRounds = 12
    const hashedPassword = await bcrypt.hash(password, saltRounds)

    // Создание пользователя
    const user = new User({
      username: cleanUsername,
      email: email.toLowerCase(),
      password: hashedPassword,
      displayName: displayName.trim(),
      avatar: avatar || "😊",
      bio: "Привет! Я использую ACTO Messenger",
      isOnline: true,
      lastSeen: new Date(),
    })

    await user.save()

    // Создание JWT токена
    const token = jwt.sign(
      {
        userId: user._id,
        username: user.username,
        iat: Math.floor(Date.now() / 1000),
      },
      JWT_SECRET,
      { expiresIn: "7d" },
    )

    // Логирование успешной регистрации
    console.log(`✅ Новый пользователь зарегистрирован: ${user.username} (${user.email})`)

    res.status(201).json({
      success: true,
      message: "Регистрация успешна",
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        displayName: user.displayName,
        avatar: user.avatar,
        bio: user.bio,
        isOnline: user.isOnline,
        createdAt: user.createdAt,
        settings: user.settings,
      },
    })
  } catch (error) {
    console.error("Ошибка регистрации:", error)

    if (error.code === 11000) {
      // Дублирование ключа
      const field = Object.keys(error.keyPattern)[0]
      return res.status(400).json({
        success: false,
        error: `${field === "username" ? "Имя пользователя" : "Email"} уже используется`,
      })
    }

    res.status(500).json({
      success: false,
      error: "Внутренняя ошибка сервера при регистрации",
    })
  }
})

// Авторизация с защитой от брутфорса
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: "Имя пользователя и пароль обязательны",
      })
    }

    // Поиск пользователя
    const user = await User.findOne({
      $or: [{ username: username.replace(/[@\s]/g, "").toLowerCase() }, { email: username.toLowerCase() }],
    })

    if (!user) {
      return res.status(400).json({
        success: false,
        error: "Неверные учетные данные",
      })
    }

    // Проверка блокировки
    if (user.isLocked) {
      return res.status(423).json({
        success: false,
        error: "Аккаунт временно заблокирован из-за множественных неудачных попыток входа",
      })
    }

    // Проверка пароля
    const isValidPassword = await bcrypt.compare(password, user.password)
    if (!isValidPassword) {
      // Увеличиваем счетчик неудачных попыток
      user.loginAttempts += 1

      if (user.loginAttempts >= 5) {
        user.lockUntil = new Date(Date.now() + 15 * 60 * 1000) // 15 минут
        console.log(`🔒 Аккаунт заблокирован: ${user.username}`)
      }

      await user.save()

      return res.status(400).json({
        success: false,
        error: "Неверные учетные данные",
      })
    }

    // Сброс счетчика попыток при успешном входе
    if (user.loginAttempts > 0) {
      user.loginAttempts = 0
      user.lockUntil = undefined
    }

    // Обновление статуса онлайн
    user.isOnline = true
    user.lastSeen = new Date()
    await user.save()

    // Создание JWT токена
    const token = jwt.sign(
      {
        userId: user._id,
        username: user.username,
        iat: Math.floor(Date.now() / 1000),
      },
      JWT_SECRET,
      { expiresIn: "7d" },
    )

    console.log(`✅ Пользователь вошел: ${user.username}`)

    res.json({
      success: true,
      message: "Вход выполнен успешно",
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        displayName: user.displayName,
        avatar: user.avatar,
        bio: user.bio,
        isOnline: user.isOnline,
        createdAt: user.createdAt,
        settings: user.settings,
      },
    })
  } catch (error) {
    console.error("Ошибка авторизации:", error)
    res.status(500).json({
      success: false,
      error: "Внутренняя ошибка сервера при авторизации",
    })
  }
})

// Получение профиля
app.get("/api/auth/profile", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("-password -loginAttempts -lockUntil")
    if (!user) {
      return res.status(404).json({
        success: false,
        error: "Пользователь не найден",
      })
    }

    res.json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        displayName: user.displayName,
        avatar: user.avatar,
        bio: user.bio,
        isOnline: user.isOnline,
        lastSeen: user.lastSeen,
        createdAt: user.createdAt,
        settings: user.settings,
      },
    })
  } catch (error) {
    console.error("Ошибка получения профиля:", error)
    res.status(500).json({
      success: false,
      error: "Внутренняя ошибка сервера",
    })
  }
})

// Обновление профиля
app.put("/api/auth/profile", authenticateToken, async (req, res) => {
  try {
    const { displayName, avatar, bio, settings } = req.body

    const user = await User.findById(req.user.userId)
    if (!user) {
      return res.status(404).json({
        success: false,
        error: "Пользователь не найден",
      })
    }

    // Валидация обновляемых данных
    if (displayName !== undefined) {
      if (!displayName || displayName.length < 2 || displayName.length > 50) {
        return res.status(400).json({
          success: false,
          error: "Отображаемое имя должно содержать от 2 до 50 символов",
        })
      }
      user.displayName = displayName.trim()
    }

    if (avatar !== undefined) {
      user.avatar = avatar
    }

    if (bio !== undefined) {
      if (bio.length > 200) {
        return res.status(400).json({
          success: false,
          error: "Биография не может превышать 200 символов",
        })
      }
      user.bio = bio
    }

    if (settings !== undefined) {
      user.settings = { ...user.settings, ...settings }
    }

    await user.save()

    console.log(`📝 Профиль обновлен: ${user.username}`)

    res.json({
      success: true,
      message: "Профиль успешно обновлен",
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        displayName: user.displayName,
        avatar: user.avatar,
        bio: user.bio,
        isOnline: user.isOnline,
        lastSeen: user.lastSeen,
        createdAt: user.createdAt,
        settings: user.settings,
      },
    })
  } catch (error) {
    console.error("Ошибка обновления профиля:", error)
    res.status(500).json({
      success: false,
      error: "Внутренняя ошибка сервера",
    })
  }
})

// Выход
app.post("/api/auth/logout", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId)
    if (user) {
      user.isOnline = false
      user.lastSeen = new Date()
      user.socketId = null
      await user.save()
      console.log(`👋 Пользователь вышел: ${user.username}`)
    }

    res.json({
      success: true,
      message: "Выход выполнен успешно",
    })
  } catch (error) {
    console.error("Ошибка выхода:", error)
    res.status(500).json({
      success: false,
      error: "Внутренняя ошибка сервера",
    })
  }
})

// Поиск пользователей
app.get("/api/users/search", authenticateToken, async (req, res) => {
  try {
    const { q } = req.query
    if (!q || q.length < 2) {
      return res.json({ success: true, users: [] })
    }

    const searchRegex = new RegExp(q, "i")
    const users = await User.find({
      $and: [
        { _id: { $ne: req.user.userId } },
        {
          $or: [{ username: searchRegex }, { displayName: searchRegex }, { email: searchRegex }],
        },
      ],
    })
      .select("username displayName avatar isOnline lastSeen createdAt")
      .limit(20)
      .sort({ isOnline: -1, lastSeen: -1 })

    res.json({
      success: true,
      users: users.map((user) => ({
        id: user._id,
        username: user.username,
        displayName: user.displayName,
        avatar: user.avatar,
        isOnline: user.isOnline,
        lastSeen: user.lastSeen,
        createdAt: user.createdAt,
      })),
    })
  } catch (error) {
    console.error("Ошибка поиска пользователей:", error)
    res.status(500).json({
      success: false,
      error: "Внутренняя ошибка сервера",
    })
  }
})

// Получение чатов
app.get("/api/chats", authenticateToken, async (req, res) => {
  try {
    const chats = await Chat.find({
      participants: req.user.userId,
      isArchived: { $ne: true },
    })
      .populate("participants", "username displayName avatar isOnline lastSeen")
      .populate({
        path: "lastMessage",
        populate: {
          path: "senderId",
          select: "username displayName avatar",
        },
      })
      .sort({ updatedAt: -1 })

    const formattedChats = await Promise.all(
      chats.map(async (chat) => {
        let chatName = chat.name
        let chatAvatar = chat.avatar

        // Для приватных чатов получаем данные собеседника
        if (chat.type === "private") {
          const otherUser = chat.participants.find((p) => p._id.toString() !== req.user.userId)
          if (otherUser) {
            chatName = otherUser.displayName
            chatAvatar = otherUser.avatar
          }
        }

        // Подсчет непрочитанных сообщений
        const unreadCount = await Message.countDocuments({
          chatId: chat._id,
          senderId: { $ne: req.user.userId },
          "readBy.userId": { $ne: req.user.userId },
          isDeleted: { $ne: true },
        })

        return {
          id: chat._id,
          type: chat.type,
          name: chatName,
          description: chat.description,
          avatar: chatAvatar,
          participants: chat.participants.map((p) => ({
            id: p._id,
            username: p.username,
            displayName: p.displayName,
            avatar: p.avatar,
            isOnline: p.isOnline,
            lastSeen: p.lastSeen,
          })),
          lastMessage: chat.lastMessage
            ? {
                id: chat.lastMessage._id,
                content: chat.lastMessage.content,
                type: chat.lastMessage.type,
                senderId: chat.lastMessage.senderId._id,
                senderName: chat.lastMessage.senderId.displayName,
                timestamp: chat.lastMessage.createdAt,
              }
            : null,
          unreadCount,
          isPinned: chat.isPinned,
          createdAt: chat.createdAt,
          updatedAt: chat.updatedAt,
        }
      }),
    )

    res.json({
      success: true,
      chats: formattedChats,
    })
  } catch (error) {
    console.error("Ошибка получения чатов:", error)
    res.status(500).json({
      success: false,
      error: "Внутренняя ошибка сервера",
    })
  }
})

// Создание чата
app.post("/api/chats", authenticateToken, async (req, res) => {
  try {
    const { type, name, description, participants } = req.body

    if (type === "private") {
      // Для приватного чата нужен только один участник
      if (!participants || participants.length !== 1) {
        return res.status(400).json({
          success: false,
          error: "Для приватного чата нужен один участник",
        })
      }

      // Проверяем существование пользователя
      const otherUser = await User.findById(participants[0])
      if (!otherUser) {
        return res.status(404).json({
          success: false,
          error: "Пользователь не найден",
        })
      }

      // Проверяем, существует ли уже приватный чат
      const existingChat = await Chat.findOne({
        type: "private",
        participants: {
          $all: [req.user.userId, participants[0]],
          $size: 2,
        },
      }).populate("participants", "username displayName avatar isOnline lastSeen")

      if (existingChat) {
        return res.json({
          success: true,
          chat: {
            id: existingChat._id,
            type: existingChat.type,
            participants: existingChat.participants,
            createdAt: existingChat.createdAt,
          },
          message: "Чат уже существует",
        })
      }

      const chat = new Chat({
        type: "private",
        participants: [req.user.userId, participants[0]],
      })

      await chat.save()
      await chat.populate("participants", "username displayName avatar isOnline lastSeen")

      console.log(`💬 Создан приватный чат между ${req.user.username} и ${otherUser.username}`)

      res.status(201).json({
        success: true,
        chat: {
          id: chat._id,
          type: chat.type,
          participants: chat.participants,
          createdAt: chat.createdAt,
        },
        message: "Приватный чат создан",
      })
    } else {
      // Для групп и каналов
      if (!name || name.length < 2 || name.length > 100) {
        return res.status(400).json({
          success: false,
          error: "Название должно содержать от 2 до 100 символов",
        })
      }

      if (description && description.length > 500) {
        return res.status(400).json({
          success: false,
          error: "Описание не может превышать 500 символов",
        })
      }

      // Проверяем существование участников
      if (participants && participants.length > 0) {
        const existingUsers = await User.find({ _id: { $in: participants } })
        if (existingUsers.length !== participants.length) {
          return res.status(400).json({
            success: false,
            error: "Некоторые пользователи не найдены",
          })
        }
      }

      const chat = new Chat({
        type,
        name: name.trim(),
        description: description?.trim(),
        avatar: type === "group" ? "👥" : "📢",
        participants: [req.user.userId, ...(participants || [])],
        admins: [req.user.userId],
        owner: req.user.userId,
      })

      await chat.save()
      await chat.populate("participants", "username displayName avatar isOnline lastSeen")

      console.log(`👥 Создан ${type} чат: ${chat.name} (${req.user.username})`)

      res.status(201).json({
        success: true,
        chat: {
          id: chat._id,
          type: chat.type,
          name: chat.name,
          description: chat.description,
          avatar: chat.avatar,
          participants: chat.participants,
          createdAt: chat.createdAt,
        },
        message: `${type === "group" ? "Группа" : "Канал"} создан${type === "group" ? "а" : ""}`,
      })
    }
  } catch (error) {
    console.error("Ошибка создания чата:", error)
    res.status(500).json({
      success: false,
      error: "Внутренняя ошибка сервера",
    })
  }
})

// Получение сообщений
app.get("/api/messages/:chatId", authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params
    const { page = 1, limit = 50 } = req.query

    // Проверяем доступ к чату
    const chat = await Chat.findOne({
      _id: chatId,
      participants: req.user.userId,
    })

    if (!chat) {
      return res.status(403).json({
        success: false,
        error: "Доступ к чату запрещен",
      })
    }

    const messages = await Message.find({
      chatId,
      isDeleted: { $ne: true },
    })
      .populate("senderId", "username displayName avatar")
      .populate({
        path: "replyTo",
        populate: {
          path: "senderId",
          select: "username displayName avatar",
        },
      })
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)

    res.json({
      success: true,
      messages: messages.reverse().map((msg) => ({
        id: msg._id,
        chatId: msg.chatId,
        senderId: msg.senderId._id,
        senderUsername: msg.senderId.username,
        senderDisplayName: msg.senderId.displayName,
        senderAvatar: msg.senderId.avatar,
        content: msg.content,
        type: msg.type,
        fileUrl: msg.fileUrl,
        fileName: msg.fileName,
        fileSize: msg.fileSize,
        fileMimeType: msg.fileMimeType,
        replyTo: msg.replyTo
          ? {
              id: msg.replyTo._id,
              content: msg.replyTo.content,
              senderId: msg.replyTo.senderId._id,
              senderName: msg.replyTo.senderId.displayName,
            }
          : null,
        edited: msg.edited,
        editedAt: msg.editedAt,
        timestamp: msg.createdAt,
        readBy: msg.readBy,
        reactions: msg.reactions,
      })),
      pagination: {
        page: Number.parseInt(page),
        limit: Number.parseInt(limit),
        hasMore: messages.length === Number.parseInt(limit),
      },
    })
  } catch (error) {
    console.error("Ошибка получения сообщений:", error)
    res.status(500).json({
      success: false,
      error: "Внутренняя ошибка сервера",
    })
  }
})

// Отправка сообщения
app.post("/api/messages/:chatId", authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params
    const { content, type = "text", replyTo, fileUrl, fileName, fileSize, fileMimeType } = req.body

    // Проверяем доступ к чату
    const chat = await Chat.findOne({
      _id: chatId,
      participants: req.user.userId,
    })

    if (!chat) {
      return res.status(403).json({
        success: false,
        error: "Доступ к чату запрещен",
      })
    }

    // Валидация контента
    if (type === "text" && (!content || content.trim().length === 0)) {
      return res.status(400).json({
        success: false,
        error: "Сообщение не может быть пустым",
      })
    }

    if (content && content.length > 4000) {
      return res.status(400).json({
        success: false,
        error: "Сообщение слишком длинное (максимум 4000 символов)",
      })
    }

    // Проверяем существование сообщения для ответа
    if (replyTo) {
      const replyMessage = await Message.findOne({
        _id: replyTo,
        chatId: chatId,
        isDeleted: { $ne: true },
      })
      if (!replyMessage) {
        return res.status(400).json({
          success: false,
          error: "Сообщение для ответа не найдено",
        })
      }
    }

    const message = new Message({
      chatId,
      senderId: req.user.userId,
      content: content?.trim(),
      type,
      replyTo,
      fileUrl,
      fileName,
      fileSize,
      fileMimeType,
    })

    await message.save()
    await message.populate("senderId", "username displayName avatar")

    // Обновляем последнее сообщение в чате
    chat.lastMessage = message._id
    chat.updatedAt = new Date()
    await chat.save()

    const formattedMessage = {
      id: message._id,
      chatId: message.chatId,
      senderId: message.senderId._id,
      senderUsername: message.senderId.username,
      senderDisplayName: message.senderId.displayName,
      senderAvatar: message.senderId.avatar,
      content: message.content,
      type: message.type,
      fileUrl: message.fileUrl,
      fileName: message.fileName,
      fileSize: message.fileSize,
      fileMimeType: message.fileMimeType,
      replyTo: message.replyTo,
      timestamp: message.createdAt,
      reactions: message.reactions,
    }

    // Отправляем через Socket.IO
    io.to(chatId).emit("new-message", formattedMessage)

    console.log(`📨 Сообщение отправлено в чат ${chatId} от ${message.senderId.username}`)

    res.status(201).json({
      success: true,
      message: formattedMessage,
    })
  } catch (error) {
    console.error("Ошибка отправки сообщения:", error)
    res.status(500).json({
      success: false,
      error: "Внутренняя ошибка сервера",
    })
  }
})

// Загрузка файлов
app.post("/api/upload", authenticateToken, upload.single("file"), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: "Файл не загружен",
      })
    }

    const fileUrl = `/uploads/${req.file.filename}`

    console.log(`📎 Файл загружен: ${req.file.originalname} (${req.file.size} bytes)`)

    res.json({
      success: true,
      file: {
        url: fileUrl,
        name: req.file.originalname,
        size: req.file.size,
        type: req.file.mimetype,
      },
    })
  } catch (error) {
    console.error("Ошибка загрузки файла:", error)
    res.status(500).json({
      success: false,
      error: "Ошибка загрузки файла",
    })
  }
})

// Получение стикеров
app.get("/api/stickers", (req, res) => {
  res.json({
    success: true,
    stickers: STICKERS,
  })
})

// Отметка как прочитанное
app.post("/api/chats/:chatId/read", authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params

    const result = await Message.updateMany(
      {
        chatId,
        senderId: { $ne: req.user.userId },
        "readBy.userId": { $ne: req.user.userId },
        isDeleted: { $ne: true },
      },
      {
        $push: {
          readBy: {
            userId: req.user.userId,
            readAt: new Date(),
          },
        },
      },
    )

    console.log(`👁️ Отмечено как прочитанное ${result.modifiedCount} сообщений в чате ${chatId}`)

    res.json({
      success: true,
      markedAsRead: result.modifiedCount,
    })
  } catch (error) {
    console.error("Ошибка отметки прочтения:", error)
    res.status(500).json({
      success: false,
      error: "Внутренняя ошибка сервера",
    })
  }
})

// Статистика API
app.get("/api/stats", authenticateToken, async (req, res) => {
  try {
    const [userCount, chatCount, messageCount] = await Promise.all([
      User.countDocuments(),
      Chat.countDocuments({ participants: req.user.userId }),
      Message.countDocuments({ senderId: req.user.userId, isDeleted: { $ne: true } }),
    ])

    res.json({
      success: true,
      stats: {
        totalUsers: userCount,
        userChats: chatCount,
        userMessages: messageCount,
        serverUptime: process.uptime(),
        memoryUsage: process.memoryUsage(),
      },
    })
  } catch (error) {
    console.error("Ошибка получения статистики:", error)
    res.status(500).json({
      success: false,
      error: "Внутренняя ошибка сервера",
    })
  }
})

// Socket.IO обработчики
io.on("connection", (socket) => {
  console.log(`👤 Пользователь подключен: ${socket.id}`)

  // Аутентификация пользователя
  socket.on("authenticate", async (token) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET)
      const user = await User.findById(decoded.userId)

      if (user) {
        socket.userId = user._id.toString()
        socket.username = user.username

        // Обновляем socketId и статус онлайн
        user.socketId = socket.id
        user.isOnline = true
        user.lastSeen = new Date()
        await user.save()

        // Присоединяемся к чатам пользователя
        const chats = await Chat.find({ participants: user._id })
        chats.forEach((chat) => {
          socket.join(chat._id.toString())
        })

        socket.emit("authenticated", {
          success: true,
          user: {
            id: user._id,
            username: user.username,
            displayName: user.displayName,
            avatar: user.avatar,
            isOnline: user.isOnline,
          },
        })

        // Уведомляем других пользователей о том, что пользователь онлайн
        socket.broadcast.emit("user-online", {
          userId: user._id,
          username: user.username,
          displayName: user.displayName,
        })

        console.log(`✅ Пользователь аутентифицирован: ${user.username} (${user.displayName})`)
      }
    } catch (error) {
      console.error("Ошибка аутентификации Socket.IO:", error)
      socket.emit("auth-error", { error: "Недействительный токен" })
    }
  })

  // Присоединение к чату
  socket.on("join-chat", (chatId) => {
    socket.join(chatId)
    console.log(`👥 ${socket.username} присоединился к чату ${chatId}`)
  })

  // Покидание чата
  socket.on("leave-chat", (chatId) => {
    socket.leave(chatId)
    console.log(`👋 ${socket.username} покинул чат ${chatId}`)
  })

  // Печатание
  socket.on("typing", (data) => {
    socket.to(data.chatId).emit("user-typing", {
      userId: socket.userId,
      username: socket.username,
      chatId: data.chatId,
    })
  })

  // Остановка печатания
  socket.on("stop-typing", (data) => {
    socket.to(data.chatId).emit("user-stop-typing", {
      userId: socket.userId,
      username: socket.username,
      chatId: data.chatId,
    })
  })

  // Реакция на сообщение
  socket.on("message-reaction", async (data) => {
    try {
      const { messageId, emoji } = data
      const message = await Message.findById(messageId)

      if (message) {
        // Проверяем, есть ли уже реакция от этого пользователя
        const existingReaction = message.reactions.find(
          (r) => r.userId.toString() === socket.userId && r.emoji === emoji,
        )

        if (existingReaction) {
          // Удаляем реакцию
          message.reactions = message.reactions.filter(
            (r) => !(r.userId.toString() === socket.userId && r.emoji === emoji),
          )
        } else {
          // Добавляем реакцию
          message.reactions.push({
            userId: socket.userId,
            emoji: emoji,
            createdAt: new Date(),
          })
        }

        await message.save()

        // Отправляем обновление всем в чате
        io.to(message.chatId.toString()).emit("message-reaction-update", {
          messageId: message._id,
          reactions: message.reactions,
        })
      }
    } catch (error) {
      console.error("Ошибка реакции на сообщение:", error)
    }
  })

  // Отключение
  socket.on("disconnect", async () => {
    if (socket.userId) {
      try {
        const user = await User.findById(socket.userId)
        if (user) {
          user.isOnline = false
          user.lastSeen = new Date()
          user.socketId = null
          await user.save()

          // Уведомляем других пользователей о том, что пользователь офлайн
          socket.broadcast.emit("user-offline", {
            userId: user._id,
            username: user.username,
            lastSeen: user.lastSeen,
          })
        }
        console.log(`❌ Пользователь отключен: ${socket.username}`)
      } catch (error) {
        console.error("Ошибка при отключении:", error)
      }
    }
  })
})

// Обработка ошибок
app.use((error, req, res, next) => {
  console.error("Ошибка сервера:", error)

  if (error instanceof multer.MulterError) {
    if (error.code === "LIMIT_FILE_SIZE") {
      return res.status(400).json({
        success: false,
        error: "Файл слишком большой (максимум 100MB)",
      })
    }
  }

  res.status(500).json({
    success: false,
    error: "Внутренняя ошибка сервера",
  })
})

// 404 обработчик
app.use("*", (req, res) => {
  res.status(404).json({
    success: false,
    error: "Эндпоинт не найден",
    availableEndpoints: [
      "GET /",
      "POST /api/auth/register",
      "POST /api/auth/login",
      "GET /api/auth/profile",
      "PUT /api/auth/profile",
      "POST /api/auth/logout",
      "GET /api/users/search",
      "GET /api/chats",
      "POST /api/chats",
      "GET /api/messages/:chatId",
      "POST /api/messages/:chatId",
      "POST /api/upload",
      "GET /api/stickers",
      "POST /api/chats/:chatId/read",
      "GET /api/stats",
    ],
  })
})

// Запуск сервера
const PORT = process.env.PORT || 3000
server.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 ACTO Messenger сервер запущен на порту ${PORT}`)
  console.log(`🌐 API: http://localhost:${PORT}`)
  console.log(`📁 Загрузки: http://localhost:${PORT}/uploads`)
  console.log(`🗄️ База данных: MongoDB Atlas`)
  console.log(`🔐 JWT Secret: ${JWT_SECRET.substring(0, 10)}...`)
  console.log(`📊 Память: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)} MB`)
})

// Graceful shutdown
const gracefulShutdown = async (signal) => {
  console.log(`🛑 Получен сигнал ${signal}, завершение работы...`)

  // Обновляем всех пользователей как офлайн
  try {
    await User.updateMany(
      { isOnline: true },
      {
        isOnline: false,
        lastSeen: new Date(),
        socketId: null,
      },
    )
    console.log("👥 Все пользователи отмечены как офлайн")
  } catch (error) {
    console.error("Ошибка при обновлении статусов пользователей:", error)
  }

  // Закрываем подключение к MongoDB
  try {
    await mongoose.connection.close()
    console.log("🗄️ Подключение к MongoDB закрыто")
  } catch (error) {
    console.error("Ошибка при закрытии подключения к MongoDB:", error)
  }

  server.close(() => {
    console.log("✅ Сервер остановлен")
    process.exit(0)
  })

  // Принудительное завершение через 10 секунд
  setTimeout(() => {
    console.log("⏰ Принудительное завершение работы")
    process.exit(1)
  }, 10000)
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"))
process.on("SIGINT", () => gracefulShutdown("SIGINT"))

// Обработка необработанных исключений
process.on("unhandledRejection", (reason, promise) => {
  console.error("Необработанное отклонение Promise:", promise, "причина:", reason)
})

process.on("uncaughtException", (error) => {
  console.error("Необработанное исключение:", error)
  gracefulShutdown("UNCAUGHT_EXCEPTION")
})
