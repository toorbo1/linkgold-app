const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const jwt = require('jsonwebtoken');
const { Telegraf } = require('telegraf');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'linkgold-secret-key-2024';
const BOT_TOKEN = process.env.BOT_TOKEN || 'your-telegram-bot-token';

// Инициализация бота Telegram
const bot = new Telegraf(BOT_TOKEN);

// Для Railway - используем абсолютный путь к БД
const dbPath = process.env.NODE_ENV === 'production' 
  ? '/tmp/linkgold.db' 
  : path.join(__dirname, 'linkgold.db');

console.log('📊 Путь к базе данных:', dbPath);

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('❌ Ошибка подключения к базе данных:', err);
  } else {
    console.log('✅ Подключение к SQLite базе данных установлено');
  }
});

// Создание таблиц
function initializeDatabase() {
  return new Promise((resolve, reject) => {
    db.serialize(() => {
      // Таблица пользователей
      db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        telegram_id TEXT UNIQUE,
        username TEXT,
        first_name TEXT,
        balance REAL DEFAULT 0,
        completed_tasks INTEGER DEFAULT 0,
        active_tasks INTEGER DEFAULT 0,
        level INTEGER DEFAULT 0,
        level_progress INTEGER DEFAULT 0,
        is_admin BOOLEAN DEFAULT 0,
        is_main_admin BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`, (err) => {
        if (err) console.error('Ошибка создания таблицы users:', err);
      });

      // Таблица заданий
      db.run(`CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        category TEXT,
        price REAL,
        description TEXT,
        time TEXT,
        link TEXT,
        admin_id TEXT,
        available INTEGER DEFAULT 10,
        status TEXT DEFAULT 'active',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT 1
      )`, (err) => {
        if (err) console.error('Ошибка создания таблицы tasks:', err);
      });

      // Таблица выполненных заданий
      db.run(`CREATE TABLE IF NOT EXISTS user_tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,
        task_id INTEGER,
        status TEXT DEFAULT 'pending',
        photo_url TEXT,
        comment TEXT,
        submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        reviewed_at DATETIME,
        reviewed_by TEXT
      )`, (err) => {
        if (err) console.error('Ошибка создания таблицы user_tasks:', err);
      });

      // Таблица сообщений поддержки
      db.run(`CREATE TABLE IF NOT EXISTS support_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,
        message TEXT,
        admin_id TEXT,
        admin_reply TEXT,
        status TEXT DEFAULT 'open',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        replied_at DATETIME
      )`, (err) => {
        if (err) console.error('Ошибка создания таблицы support_messages:', err);
      });

      // Таблица чатов
      db.run(`CREATE TABLE IF NOT EXISTS chats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,
        message TEXT,
        is_admin BOOLEAN DEFAULT 0,
        admin_id TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`, (err) => {
        if (err) console.error('Ошибка создания таблицы chats:', err);
      });

      // Создаем главного администратора
      db.get('SELECT * FROM users WHERE telegram_id = "8036875641"', (err, row) => {
        if (err) console.error('Ошибка проверки администратора:', err);
        
        if (!row) {
          db.run(`INSERT INTO users (telegram_id, username, first_name, is_admin, is_main_admin) 
                  VALUES ('8036875641', '@LinkGoldAssistant', 'LinkGold Assistant', 1, 1)`, (err) => {
            if (err) {
              console.error('Ошибка создания администратора:', err);
            } else {
              console.log('✅ Главный администратор создан');
            }
          });
        }
      });
      
      // Добавляем тестовые задания
      db.get('SELECT COUNT(*) as count FROM tasks', (err, row) => {
        if (err) console.error('Ошибка проверки заданий:', err);
        
        if (row && row.count === 0) {
          const demoTasks = [
            ['Подписка на Telegram канал', 'subscribe', 15, 'Подпишитесь на наш Telegram канал и оставайтесь подписанным минимум 3 дня.', '5 мин', 'https://t.me/linkgold_channel', '8036875641'],
            ['Просмотр YouTube видео', 'view', 10, 'Посмотрите видео на YouTube до конца и поставьте лайк.', '10 мин', 'https://youtube.com/watch?v=example', '8036875641'],
            ['Комментарий в группе', 'comment', 20, 'Оставьте содержательный комментарий в указанной группе.', '7 мин', 'https://t.me/test_group', '8036875641']
          ];
          
          const stmt = db.prepare(`INSERT INTO tasks (title, category, price, description, time, link, admin_id) VALUES (?, ?, ?, ?, ?, ?, ?)`);
          
          demoTasks.forEach(task => {
            stmt.run(task, (err) => {
              if (err) {
                console.error('Ошибка добавления демо-задания:', err);
              }
            });
          });
          
          stmt.finalize();
          console.log('✅ Демо-задания добавлены');
        }
        
        resolve();
      });
    });
  });
}

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Обслуживание статических файлов
app.use(express.static(path.join(__dirname, 'public')));

// Middleware для логирования
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Middleware для проверки JWT токена
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, error: 'Токен отсутствует' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, error: 'Неверный токен' });
    }
    req.user = user;
    next();
  });
};

// API Routes

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    success: true,
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Регистрация/авторизация через Telegram
app.post('/api/auth/telegram', (req, res) => {
  const { telegramId, username, firstName } = req.body;

  if (!telegramId) {
    return res.status(400).json({ success: false, error: 'Telegram ID обязателен' });
  }

  // Проверяем существующего пользователя
  db.get('SELECT * FROM users WHERE telegram_id = ?', [telegramId], (err, user) => {
    if (err) {
      console.error('Ошибка базы данных:', err);
      return res.status(500).json({ success: false, error: 'Ошибка базы данных' });
    }

    if (user) {
      // Пользователь существует - обновляем данные если изменились
      if (user.username !== username || user.first_name !== firstName) {
        db.run('UPDATE users SET username = ?, first_name = ? WHERE telegram_id = ?', 
          [username, firstName, telegramId]);
      }
      
      const token = jwt.sign(
        { 
          telegramId: user.telegram_id, 
          username: user.username,
          isAdmin: user.is_admin === 1, 
          isMainAdmin: user.is_main_admin === 1 
        },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      res.json({ 
        success: true,
        token, 
        user: {
          telegramId: user.telegram_id,
          username: user.username,
          firstName: user.first_name,
          balance: user.balance,
          completedTasks: user.completed_tasks,
          activeTasks: user.active_tasks,
          level: user.level,
          levelProgress: user.level_progress,
          isAdmin: user.is_admin === 1,
          isMainAdmin: user.is_main_admin === 1
        }
      });
    } else {
      // Новый пользователь
      db.run(
        'INSERT INTO users (telegram_id, username, first_name) VALUES (?, ?, ?)',
        [telegramId, username || `user_${telegramId}`, firstName || 'User'],
        function(err) {
          if (err) {
            console.error('Ошибка создания пользователя:', err);
            return res.status(500).json({ success: false, error: 'Ошибка создания пользователя' });
          }

          const token = jwt.sign(
            { 
              telegramId, 
              username: username || `user_${telegramId}`,
              isAdmin: false, 
              isMainAdmin: false 
            },
            JWT_SECRET,
            { expiresIn: '24h' }
          );

          res.json({ 
            success: true,
            token,
            user: {
              telegramId,
              username: username || `user_${telegramId}`,
              firstName: firstName || 'User',
              balance: 0,
              completedTasks: 0,
              activeTasks: 0,
              level: 0,
              levelProgress: 0,
              isAdmin: false,
              isMainAdmin: false
            }
          });
        }
      );
    }
  });
});

// Получение заданий с поиском и фильтрацией
app.get('/api/tasks', authenticateToken, (req, res) => {
  const { search, category } = req.query;
  let query = 'SELECT * FROM tasks WHERE is_active = 1';
  const params = [];

  if (search) {
    query += ' AND (title LIKE ? OR description LIKE ?)';
    params.push(`%${search}%`, `%${search}%`);
  }

  if (category && category !== 'all') {
    query += ' AND category = ?';
    params.push(category);
  }

  query += ' ORDER BY created_at DESC';

  db.all(query, params, (err, tasks) => {
    if (err) {
      console.error('Ошибка получения заданий:', err);
      return res.status(500).json({ success: false, error: 'Ошибка базы данных' });
    }
    res.json({ success: true, tasks: tasks || [] });
  });
});

// Запуск задания
app.post('/api/tasks/start', authenticateToken, (req, res) => {
  const { taskId } = req.body;

  if (!taskId) {
    return res.status(400).json({ success: false, error: 'ID задания обязательно' });
  }

  // Проверяем, не выполняет ли пользователь уже это задание
  db.get('SELECT * FROM user_tasks WHERE user_id = ? AND task_id = ? AND status = "pending"', 
    [req.user.telegramId, taskId], (err, existingTask) => {
      if (err) {
        console.error('Ошибка проверки задания:', err);
        return res.status(500).json({ success: false, error: 'Ошибка базы данных' });
      }

      if (existingTask) {
        return res.status(400).json({ success: false, error: 'Вы уже выполняете это задание' });
      }

      // Создаем запись о начале выполнения задания
      db.run('INSERT INTO user_tasks (user_id, task_id) VALUES (?, ?)',
        [req.user.telegramId, taskId], function(err) {
          if (err) {
            console.error('Ошибка начала задания:', err);
            return res.status(500).json({ success: false, error: 'Ошибка начала задания' });
          }

          // Обновляем счетчик активных заданий
          db.run('UPDATE users SET active_tasks = active_tasks + 1 WHERE telegram_id = ?', 
            [req.user.telegramId], (err) => {
              if (err) console.error('Ошибка обновления активных заданий:', err);
            });

          res.json({ success: true, message: 'Задание начато' });
        });
    });
});

// Отправка задания на проверку
app.post('/api/tasks/submit', authenticateToken, (req, res) => {
  const { taskId, photoUrl, comment } = req.body;

  if (!taskId) {
    return res.status(400).json({ success: false, error: 'ID задания обязательно' });
  }

  db.run(
    'UPDATE user_tasks SET photo_url = ?, comment = ?, status = "pending", submitted_at = CURRENT_TIMESTAMP WHERE user_id = ? AND task_id = ? AND status = "pending"',
    [photoUrl || '', comment || '', req.user.telegramId, taskId],
    function(err) {
      if (err) {
        console.error('Ошибка отправки задания:', err);
        return res.status(500).json({ success: false, error: 'Ошибка отправки задания' });
      }

      if (this.changes === 0) {
        return res.status(404).json({ success: false, error: 'Задание не найдено или уже отправлено' });
      }

      res.json({ success: true, message: 'Задание отправлено на проверку' });
    }
  );
});

// Получение заданий пользователя
app.get('/api/user/tasks', authenticateToken, (req, res) => {
  const { status } = req.query;
  let query = `
    SELECT ut.*, t.title, t.price, t.category 
    FROM user_tasks ut 
    JOIN tasks t ON ut.task_id = t.id 
    WHERE ut.user_id = ?
  `;
  const params = [req.user.telegramId];

  if (status) {
    query += ' AND ut.status = ?';
    params.push(status);
  }

  query += ' ORDER BY ut.submitted_at DESC';

  db.all(query, params, (err, tasks) => {
    if (err) {
      console.error('Ошибка получения заданий пользователя:', err);
      return res.status(500).json({ success: false, error: 'Ошибка базы данных' });
    }
    res.json({ success: true, tasks: tasks || [] });
  });
});

// Чат поддержки
app.get('/api/chat/messages', authenticateToken, (req, res) => {
  db.all(
    `SELECT c.*, u.username, u.first_name 
     FROM chats c 
     LEFT JOIN users u ON c.admin_id = u.telegram_id 
     WHERE c.user_id = ? 
     ORDER BY c.created_at ASC`,
    [req.user.telegramId],
    (err, messages) => {
      if (err) {
        console.error('Ошибка получения сообщений:', err);
        return res.status(500).json({ success: false, error: 'Ошибка базы данных' });
      }
      res.json({ success: true, messages: messages || [] });
    }
  );
});

app.post('/api/chat/messages', authenticateToken, (req, res) => {
  const { message } = req.body;

  if (!message || message.trim().length === 0) {
    return res.status(400).json({ success: false, error: 'Сообщение не может быть пустым' });
  }

  db.run(
    'INSERT INTO chats (user_id, message, is_admin) VALUES (?, ?, 0)',
    [req.user.telegramId, message.trim()],
    function(err) {
      if (err) {
        console.error('Ошибка отправки сообщения:', err);
        return res.status(500).json({ success: false, error: 'Ошибка отправки сообщения' });
      }

      // Уведомление администраторам о новом сообщении
      notifyAdminsAboutNewMessage(req.user.telegramId, req.user.username, message.trim());

      res.json({ success: true, message: 'Сообщение отправлено' });
    }
  );
});

// Ответ администратора в чат
app.post('/api/chat/admin/reply', authenticateToken, (req, res) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ success: false, error: 'Требуются права администратора' });
  }

  const { userId, message } = req.body;

  if (!userId || !message) {
    return res.status(400).json({ success: false, error: 'ID пользователя и сообщение обязательны' });
  }

  db.run(
    'INSERT INTO chats (user_id, message, is_admin, admin_id) VALUES (?, ?, 1, ?)',
    [userId, message.trim(), req.user.telegramId],
    function(err) {
      if (err) {
        console.error('Ошибка отправки ответа:', err);
        return res.status(500).json({ success: false, error: 'Ошибка отправки ответа' });
      }

      // Уведомление пользователя о ответе
      notifyUserAboutReply(userId, message.trim());

      res.json({ success: true, message: 'Ответ отправлен' });
    }
  );
});

// Админка - получение всех чатов
app.get('/api/admin/chats', authenticateToken, (req, res) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ success: false, error: 'Требуются права администратора' });
  }

  const query = `
    SELECT DISTINCT c.user_id, u.username, u.first_name, 
           (SELECT message FROM chats WHERE user_id = c.user_id ORDER BY created_at DESC LIMIT 1) as last_message,
           (SELECT created_at FROM chats WHERE user_id = c.user_id ORDER BY created_at DESC LIMIT 1) as last_message_time,
           (SELECT COUNT(*) FROM chats WHERE user_id = c.user_id AND is_admin = 0 AND admin_id IS NULL) as unread_count
    FROM chats c
    JOIN users u ON c.user_id = u.telegram_id
    ORDER BY last_message_time DESC
  `;

  db.all(query, (err, chats) => {
    if (err) {
      console.error('Ошибка получения чатов:', err);
      return res.status(500).json({ success: false, error: 'Ошибка базы данных' });
    }
    res.json({ success: true, chats: chats || [] });
  });
});

// Админка - получение сообщений конкретного пользователя
app.get('/api/admin/chats/:userId', authenticateToken, (req, res) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ success: false, error: 'Требуются права администратора' });
  }

  const { userId } = req.params;

  db.all(
    `SELECT c.*, u.username, u.first_name 
     FROM chats c 
     LEFT JOIN users u ON c.admin_id = u.telegram_id 
     WHERE c.user_id = ? 
     ORDER BY c.created_at ASC`,
    [userId],
    (err, messages) => {
      if (err) {
        console.error('Ошибка получения сообщений:', err);
        return res.status(500).json({ success: false, error: 'Ошибка базы данных' });
      }
      res.json({ success: true, messages: messages || [] });
    }
  );
});

// Добавление задания (админ)
app.post('/api/admin/tasks', authenticateToken, (req, res) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ success: false, error: 'Требуются права администратора' });
  }

  const { title, category, price, description, time, link } = req.body;

  if (!title || !category || !price || !description || !time || !link) {
    return res.status(400).json({ success: false, error: 'Все поля обязательны для заполнения' });
  }

  db.run(
    'INSERT INTO tasks (title, category, price, description, time, link, admin_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [title, category, price, description, time, link, req.user.telegramId],
    function(err) {
      if (err) {
        console.error('Ошибка создания задания:', err);
        return res.status(500).json({ success: false, error: 'Ошибка создания задания' });
      }
      res.json({ success: true, id: this.lastID, message: 'Задание создано' });
    }
  );
});

// Получение заданий на проверку (админ)
app.get('/api/admin/tasks/review', authenticateToken, (req, res) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ success: false, error: 'Требуются права администратора' });
  }

  const query = `
    SELECT ut.*, u.username, u.first_name, t.title, t.price 
    FROM user_tasks ut 
    JOIN users u ON ut.user_id = u.telegram_id 
    JOIN tasks t ON ut.task_id = t.id 
    WHERE ut.status = 'pending'
    ORDER BY ut.submitted_at DESC
  `;

  db.all(query, (err, tasks) => {
    if (err) {
      console.error('Ошибка получения заданий на проверку:', err);
      return res.status(500).json({ success: false, error: 'Ошибка базы данных' });
    }
    res.json({ success: true, tasks: tasks || [] });
  });
});

// Вспомогательные функции для уведомлений
function notifyAdminsAboutNewMessage(userId, username, message) {
  // Здесь можно добавить отправку уведомлений администраторам через Telegram
  console.log(`Новое сообщение от пользователя ${username} (${userId}): ${message}`);
}

function notifyUserAboutReply(userId, message) {
  // Здесь можно добавить отправку уведомления пользователю через Telegram
  console.log(`Ответ отправлен пользователю ${userId}: ${message}`);
}

// Обслуживание React/SPA приложения
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Обработка ошибок
app.use((err, req, res, next) => {
  console.error('❌ Необработанная ошибка:', err);
  res.status(500).json({ success: false, error: 'Внутренняя ошибка сервера' });
});

// Инициализация и запуск сервера
async function startServer() {
  try {
    await initializeDatabase();
    
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Сервер LinkGold запущен на порту ${PORT}`);
      console.log(`🌍 Режим: ${process.env.NODE_ENV || 'development'}`);
      console.log(`📊 База данных: ${dbPath}`);
    });
  } catch (error) {
    console.error('❌ Ошибка запуска сервера:', error);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Получен сигнал SIGINT. Завершение работы...');
  db.close((err) => {
    if (err) {
      console.error('❌ Ошибка закрытия базы данных:', err);
      process.exit(1);
    }
    console.log('✅ База данных закрыта');
    process.exit(0);
  });
});

// Запуск сервера
startServer();
