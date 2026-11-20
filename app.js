const express = require('express');
const path = require('path');
const cors = require('cors');
const routes = require("./routes/routerIndex");

const app = express();
const port = process.env.PORT || 3201;

app.use(cors());
app.use(express.json());

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