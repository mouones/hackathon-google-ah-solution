const app = require('./app');
const pool = require('./config/database');

const PORT = process.env.PORT || 5000;

const server = app.listen(PORT, () => {
  console.log('\n' + '='.repeat(60));
  console.log('🚀 ANTI-FRAUD PLATFORM - BACKEND SERVER');
  console.log('='.repeat(60));
  console.log(`✓ Server running on port ${PORT}`);
  console.log(`✓ Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`✓ ML Service: ${process.env.ML_SERVICE_URL}`);
  console.log(`✓ Frontend URL: ${process.env.FRONTEND_URL}`);
  console.log('\n📡 API Endpoints:');
  console.log(`   POST   http://localhost:${PORT}/api/auth/register`);
  console.log(`   POST   http://localhost:${PORT}/api/auth/login`);
  console.log(`   GET    http://localhost:${PORT}/api/auth/profile`);
  console.log(`   POST   http://localhost:${PORT}/api/email/analyze`);
  console.log(`   GET    http://localhost:${PORT}/api/email/history`);
  console.log(`   GET    http://localhost:${PORT}/health`);
  console.log('='.repeat(60) + '\n');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, closing server...');
  server.close(() => {
    console.log('Server closed');
    pool.end();
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('\nSIGINT received, closing server...');
  server.close(() => {
    console.log('Server closed');
    pool.end();
    process.exit(0);
  });
});
