import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import sqlite3 from 'sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'linkgold-secret-key-2024-production';

// Для Railway - используем абсолютный путь к БД
const dbPath = process.env.NODE_ENV === 'production' 
  ? '/tmp/linkgold.db' 
  : './linkgold.db';

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Ошибка подключения к базе данных:', err);
  } else {
    console.log('Подключение к SQLite базе данных установлено');
  }
});

// Создание таблиц
db.serialize(() => {
  // Таблица пользователей
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_id TEXT UNIQUE,
    username TEXT,
    balance REAL DEFAULT 0,
    completed_tasks INTEGER DEFAULT 0,
    active_tasks INTEGER DEFAULT 0,
    level INTEGER DEFAULT 0,
    level_progress INTEGER DEFAULT 0,
    is_admin BOOLEAN DEFAULT FALSE,
    is_main_admin BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

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
    is_active BOOLEAN DEFAULT TRUE
  )`);

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
    reviewed_by TEXT,
    FOREIGN KEY (user_id) REFERENCES users (telegram_id),
    FOREIGN KEY (task_id) REFERENCES tasks (id)
  )`);

  // Таблица сообщений
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT,
    message TEXT,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (telegram_id)
  )`);

  // Создаем главного администратора
  db.run(`INSERT OR IGNORE INTO users (telegram_id, username, is_admin, is_main_admin) 
          VALUES ('8036875641', '@LinkGoldAssistant', TRUE, TRUE)`);
  
  // Добавляем тестовые задания
  db.run(`INSERT OR IGNORE INTO tasks (title, category, price, description, time, link, admin_id) VALUES 
          ('Подписка на Telegram канал', 'subscribe', 15, 'Подпишитесь на наш Telegram канал и оставайтесь подписанным минимум 3 дня.', '5 мин', 'https://t.me/linkgold_channel', '8036875641'),
          ('Просмотр YouTube видео', 'view', 10, 'Посмотрите видео на YouTube до конца и поставьте лайк.', '10 мин', 'https://youtube.com/watch?v=example', '8036875641'),
          ('Комментарий в группе', 'comment', 20, 'Оставьте содержательный комментарий в указанной группе.', '7 мин', 'https://t.me/test_group', '8036875641'),
          ('Репост записи', 'repost', 25, 'Сделайте репост записи в своем канале или группе.', '5 мин', 'https://t.me/linkgold_news', '8036875641'),
          ('Лайк поста в Instagram', 'social', 8, 'Поставьте лайк на последней публикации в Instagram.', '3 мин', 'https://instagram.com/linkgold', '8036875641')`);
});

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
    return res.status(401).json({ error: 'Токен отсутствует' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Неверный токен' });
    }
    req.user = user;
    next();
  });
};

// API Routes

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Регистрация/авторизация через Telegram
app.post('/api/auth/telegram', async (req, res) => {
  const { telegramId, username } = req.body;

  if (!telegramId) {
    return res.status(400).json({ error: 'Telegram ID обязателен' });
  }

  try {
    // Проверяем существующего пользователя
    db.get('SELECT * FROM users WHERE telegram_id = ?', [telegramId], (err, user) => {
      if (err) {
        console.error('Ошибка базы данных:', err);
        return res.status(500).json({ error: 'Ошибка базы данных' });
      }

      if (user) {
        // Пользователь существует - обновляем username если изменился
        if (user.username !== username) {
          db.run('UPDATE users SET username = ? WHERE telegram_id = ?', [username, telegramId]);
        }
        
        const token = jwt.sign(
          { 
            telegramId: user.telegram_id, 
            isAdmin: user.is_admin, 
            isMainAdmin: user.is_main_admin 
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
            balance: user.balance,
            completedTasks: user.completed_tasks,
            activeTasks: user.active_tasks,
            level: user.level,
            levelProgress: user.level_progress,
            isAdmin: user.is_admin,
            isMainAdmin: user.is_main_admin
          }
        });
      } else {
        // Новый пользователь
        db.run(
          'INSERT INTO users (telegram_id, username) VALUES (?, ?)',
          [telegramId, username || `user_${telegramId}`],
          function(err) {
            if (err) {
              console.error('Ошибка создания пользователя:', err);
              return res.status(500).json({ error: 'Ошибка создания пользователя' });
            }

            const token = jwt.sign(
              { 
                telegramId, 
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
  } catch (error) {
    console.error('Ошибка аутентификации:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Получение заданий
app.get('/api/tasks', authenticateToken, (req, res) => {
  db.all('SELECT * FROM tasks WHERE is_active = TRUE ORDER BY created_at DESC', (err, tasks) => {
    if (err) {
      console.error('Ошибка получения заданий:', err);
      return res.status(500).json({ error: 'Ошибка базы данных' });
    }
    res.json({ success: true, tasks });
  });
});

// Поиск заданий
app.get('/api/tasks/search', authenticateToken, (req, res) => {
  const { query, category } = req.query;
  
  let sql = 'SELECT * FROM tasks WHERE is_active = TRUE';
  const params = [];
  
  if (query) {
    sql += ' AND (title LIKE ? OR description LIKE ?)';
    params.push(`%${query}%`, `%${query}%`);
  }
  
  if (category && category !== 'all') {
    sql += ' AND category = ?';
    params.push(category);
  }
  
  sql += ' ORDER BY created_at DESC';
  
  db.all(sql, params, (err, tasks) => {
    if (err) {
      console.error('Ошибка поиска заданий:', err);
      return res.status(500).json({ error: 'Ошибка базы данных' });
    }
    res.json({ success: true, tasks });
  });
});

// Добавление задания (админ)
app.post('/api/tasks', authenticateToken, (req, res) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ error: 'Требуются права администратора' });
  }

  const { title, category, price, description, time, link } = req.body;

  if (!title || !category || !price || !description || !time || !link) {
    return res.status(400).json({ error: 'Все поля обязательны для заполнения' });
  }

  db.run(
    'INSERT INTO tasks (title, category, price, description, time, link, admin_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [title, category, price, description, time, link, req.user.telegramId],
    function(err) {
      if (err) {
        console.error('Ошибка создания задания:', err);
        return res.status(500).json({ error: 'Ошибка создания задания' });
      }
      res.json({ success: true, id: this.lastID, message: 'Задание создано' });
    }
  );
});

// Отправка задания на проверку
app.post('/api/tasks/submit', authenticateToken, (req, res) => {
  const { taskId, photoUrl, comment } = req.body;

  if (!taskId) {
    return res.status(400).json({ error: 'ID задания обязательно' });
  }

  db.run(
    'INSERT INTO user_tasks (user_id, task_id, photo_url, comment) VALUES (?, ?, ?, ?)',
    [req.user.telegramId, taskId, photoUrl || '', comment || ''],
    function(err) {
      if (err) {
        console.error('Ошибка отправки задания:', err);
        return res.status(500).json({ error: 'Ошибка отправки задания' });
      }
      
      // Увеличиваем счетчик активных заданий
      db.run('UPDATE users SET active_tasks = active_tasks + 1 WHERE telegram_id = ?', [req.user.telegramId]);
      
      res.json({ success: true, message: 'Задание отправлено на проверку' });
    }
  );
});

// Получение заданий на проверку (админ)
app.get('/api/tasks/review', authenticateToken, (req, res) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ error: 'Требуются права администратора' });
  }

  const query = `
    SELECT ut.*, u.username, t.title, t.price 
    FROM user_tasks ut 
    JOIN users u ON ut.user_id = u.telegram_id 
    JOIN tasks t ON ut.task_id = t.id 
    WHERE ut.status = 'pending'
    ORDER BY ut.submitted_at DESC
  `;

  db.all(query, (err, tasks) => {
    if (err) {
      console.error('Ошибка получения заданий на проверку:', err);
      return res.status(500).json({ error: 'Ошибка базы данных' });
    }
    res.json({ success: true, tasks });
  });
});

// Проверка задания (админ)
app.post('/api/tasks/review/:id', authenticateToken, (req, res) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ error: 'Требуются права администратора' });
  }

  const { status } = req.body;
  const taskId = req.params.id;

  if (!['completed', 'rejected'].includes(status)) {
    return res.status(400).json({ error: 'Неверный статус' });
  }

  db.run(
    'UPDATE user_tasks SET status = ?, reviewed_at = CURRENT_TIMESTAMP, reviewed_by = ? WHERE id = ?',
    [status, req.user.telegramId, taskId],
    async function(err) {
      if (err) {
        console.error('Ошибка обновления задания:', err);
        return res.status(500).json({ error: 'Ошибка обновления задания' });
      }

      // Получаем информацию о задании
      db.get(`
        SELECT ut.user_id, t.price 
        FROM user_tasks ut 
        JOIN tasks t ON ut.task_id = t.id 
        WHERE ut.id = ?
      `, [taskId], (err, task) => {
        if (err) {
          console.error('Ошибка получения информации о задании:', err);
          return res.status(500).json({ error: 'Ошибка базы данных' });
        }

        if (status === 'completed') {
          // Начисляем деньги пользователю
          db.run(
            `UPDATE users 
             SET balance = balance + ?, 
                 completed_tasks = completed_tasks + 1, 
                 active_tasks = active_tasks - 1,
                 level_progress = level_progress + 1 
             WHERE telegram_id = ?`,
            [task.price, task.user_id],
            (err) => {
              if (err) {
                console.error('Ошибка начисления средств:', err);
              }
              
              // Проверяем повышение уровня
              db.get('SELECT level_progress FROM users WHERE telegram_id = ?', [task.user_id], (err, user) => {
                if (!err && user && user.level_progress >= 10) {
                  db.run('UPDATE users SET level = level + 1, level_progress = 0 WHERE telegram_id = ?', [task.user_id]);
                }
                
                res.json({ success: true, message: 'Задание принято! Деньги начислены пользователю.' });
              });
            }
          );
        } else {
          // Отклонение задания
          db.run('UPDATE users SET active_tasks = active_tasks - 1 WHERE telegram_id = ?', [task.user_id]);
          res.json({ success: true, message: 'Задание отклонено' });
        }
      });
    }
  );
});

// Сообщения поддержки
app.get('/api/messages', authenticateToken, (req, res) => {
  db.all(
    'SELECT * FROM messages WHERE user_id = ? ORDER BY created_at ASC',
    [req.user.telegramId],
    (err, messages) => {
      if (err) {
        console.error('Ошибка получения сообщений:', err);
        return res.status(500).json({ error: 'Ошибка базы данных' });
      }
      res.json({ success: true, messages });
    }
  );
});

app.post('/api/messages', authenticateToken, (req, res) => {
  const { message } = req.body;

  if (!message || message.trim().length === 0) {
    return res.status(400).json({ error: 'Сообщение не может быть пустым' });
  }

  db.run(
    'INSERT INTO messages (user_id, message) VALUES (?, ?)',
    [req.user.telegramId, message.trim()],
    function(err) {
      if (err) {
        console.error('Ошибка отправки сообщения:', err);
        return res.status(500).json({ error: 'Ошибка отправки сообщения' });
      }

      res.json({ success: true, message: 'Сообщение отправлено' });
    }
  );
});

// Ответ администратора
app.post('/api/messages/admin', authenticateToken, (req, res) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ error: 'Требуются права администратора' });
  }

  const { userId, message } = req.body;

  if (!userId || !message) {
    return res.status(400).json({ error: 'UserId и сообщение обязательны' });
  }

  db.run(
    'INSERT INTO messages (user_id, message, is_admin) VALUES (?, ?, TRUE)',
    [userId, message],
    function(err) {
      if (err) {
        console.error('Ошибка отправки ответа:', err);
        return res.status(500).json({ error: 'Ошибка отправки сообщения' });
      }

      res.json({ success: true, message: 'Ответ отправлен' });
    }
  );
});

// Получение пользователей (админ)
app.get('/api/users', authenticateToken, (req, res) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ error: 'Требуются права администратора' });
  }

  db.all('SELECT telegram_id, username, balance, completed_tasks, active_tasks, level, is_admin FROM users ORDER BY created_at DESC', (err, users) => {
    if (err) {
      console.error('Ошибка получения пользователей:', err);
      return res.status(500).json({ error: 'Ошибка базы данных' });
    }
    res.json({ success: true, users });
  });
});

// Назначение администратора
app.post('/api/users/admin', authenticateToken, (req, res) => {
  if (!req.user.isMainAdmin) {
    return res.status(403).json({ error: 'Требуются права главного администратора' });
  }

  const { telegramId } = req.body;

  if (!telegramId) {
    return res.status(400).json({ error: 'Telegram ID обязателен' });
  }

  db.run(
    'UPDATE users SET is_admin = TRUE WHERE telegram_id = ?',
    [telegramId],
    function(err) {
      if (err) {
        console.error('Ошибка назначения администратора:', err);
        return res.status(500).json({ error: 'Ошибка обновления пользователя' });
      }
      
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Пользователь не найден' });
      }
      
      res.json({ success: true, message: 'Пользователь назначен администратором' });
    }
  );
});

// Получение статистики (админ)
app.get('/api/stats', authenticateToken, (req, res) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ error: 'Требуются права администратора' });
  }

  const stats = {};

  // Общее количество пользователей
  db.get('SELECT COUNT(*) as count FROM users', (err, result) => {
    if (err) {
      console.error('Ошибка получения статистики:', err);
      return res.status(500).json({ error: 'Ошибка базы данных' });
    }
    stats.totalUsers = result.count;

    // Количество активных заданий
    db.get('SELECT COUNT(*) as count FROM tasks WHERE is_active = TRUE', (err, result) => {
      stats.activeTasks = result.count;

      // Количество заданий на проверку
      db.get('SELECT COUNT(*) as count FROM user_tasks WHERE status = "pending"', (err, result) => {
        stats.pendingTasks = result.count;

        // Общая сумма выплат
        db.get('SELECT SUM(balance) as total FROM users', (err, result) => {
          stats.totalPayouts = result.total || 0;

          res.json({ success: true, stats });
        });
      });
    });
  });
});

// Обслуживание React/SPA приложения - все остальные маршруты перенаправляем на index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Обработка ошибок
app.use((err, req, res, next) => {
  console.error('Необработанная ошибка:', err);
  res.status(500).json({ error: 'Внутренняя ошибка сервера' });
});

// Запуск сервера
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Сервер LinkGold запущен на порту ${PORT}`);
  console.log(`🌍 Режим: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 База данных: ${dbPath}`);
  console.log(`🔑 JWT Secret: ${JWT_SECRET.includes('production') ? 'PRODUCTION' : 'DEVELOPMENT'}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Получен сигнал SIGINT. Завершение работы...');
  db.close((err) => {
    if (err) {
      console.error('Ошибка закрытия базы данных:', err);
      process.exit(1);
    }
    console.log('✅ База данных закрыта');
    process.exit(0);
  });
});
