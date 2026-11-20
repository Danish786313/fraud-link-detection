const express = require('express');
const path = require('path');
const cors = require('cors');
const routes = require("./routes/routerIndex");
const { sendSuccess, sendError } = require("./utils/responseHandler");

// Global response helper functions (accessible anywhere in the app)
global.sendSuccess = sendSuccess;
global.sendError = sendError;

// Process-level unhandled error catchers
process.on('uncaughtException', (err) => {
  console.error('::: Uncaught Exception :::', err);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('::: Unhandled Promise Rejection :::', reason);
});

const app = express();
const port = process.env.PORT || 3201;

app.use(cors());
app.use(express.json());

// Attach response helper methods directly to Express res object
app.use((req, res, next) => {
  res.success = (data, message, statusCode) => sendSuccess(res, data, message, statusCode);
  res.error = (message, statusCode, error) => sendError(res, message, statusCode, error);
  next();
});

// Serve static assets from views directory (HTML, CSS, JS)
app.use(express.static(path.join(__dirname, 'views')));

// API routes
app.use('/api', routes);

// Serve frontend UI
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

// 404 handler for undefined routes
app.use((req, res, next) => {
  if (req.path.startsWith('/api')) {
    return sendError(res, `API route not found: ${req.method} ${req.originalUrl}`, 404);
  }
  return res.status(404).sendFile(path.join(__dirname, 'views', 'index.html'));
});

// Global Express Error-handling Middleware
app.use((err, req, res, next) => {
  console.error('::: Global Express Error Catcher :::', err);
  const statusCode = err.status || err.statusCode || 500;
  const message = err.message || 'Internal Server Error';
  
  if (res.headersSent) {
    return next(err);
  }

  return sendError(
    res,
    message,
    statusCode,
    process.env.NODE_ENV === 'development' ? err.stack : undefined
  );
});

app.listen(port, () => {
  console.log(`Link Guard server running at http://localhost:${port}`);
});
