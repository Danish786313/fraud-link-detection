const express = require('express');
const path = require('path');
const cors = require('cors');
const routes = require("./routes/routerIndex");
const { sendSuccess, sendError } = require("./utils/responseHandler");

// Global response helper functions (accessible anywhere in the app)
global.sendSuccess = sendSuccess;
global.sendError = sendError;

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

// Serve static files from views
app.use(express.static(path.join(__dirname, 'views')));

// API routes
app.use('/api', routes);

// Serve frontend UI
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

app.listen(port, () => {
  console.log(`Link Guard server running at http://localhost:${port}`);
});