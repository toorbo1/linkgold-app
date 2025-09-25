const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Простая проверка переменных
console.log('=== 🔧 ПРОВЕРКА КОНФИГУРАЦИИ ===');
console.log('PORT:', process.env.PORT);
console.log('NODE_ENV:', process.env.NODE_ENV);
console.log('JWT_SECRET:', process.env.JWT_SECRET ? '***' + process.env.JWT_SECRET.slice(-4) : 'NOT SET');
console.log('BOT_TOKEN:', process.env.BOT_TOKEN ? '***' + process.env.BOT_TOKEN.slice(-4) : 'NOT SET');
console.log('==============================');

// Basic middleware
app.use(cors());
app.use(express.json());

// Простой health check
app.get('/api/health', (req, res) => {
  res.json({ 
    success: true,
    message: 'Сервер работает',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Простой тестовый endpoint
app.get('/api/test', (req, res) => {
  res.json({ 
    success: true,
    message: 'Тестовый endpoint работает',
    data: {
      port: PORT,
      node_env: process.env.NODE_ENV
    }
  });
});

// Обслуживание статических файлов
app.use(express.static(path.join(__dirname, 'public')));

// Обработка SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Обработка ошибок
app.use((err, req, res, next) => {
  console.error('❌ Ошибка:', err);
  res.status(500).json({ 
    success: false, 
    error: 'Внутренняя ошибка сервера',
    details: process.env.NODE_ENV === 'development' ? err.message : 'Обратитесь к администратору'
  });
});

// Запуск сервера
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Сервер запущен на порту ${PORT}`);
  console.log(`🌍 Режим: ${process.env.NODE_ENV || 'development'}`);
  console.log(`✅ Health check: http://localhost:${PORT}/api/health`);
});
