const express = require('express');
const cors = require('cors');
require('dotenv').config();

const connectDB = require('./Config/db');
const authRoutes = require('./Routes/auth');

const app = express();

// Root route
app.get('/', (req, res) => {
  res.send('API is running...');
});

// Connect to DB
connectDB();



// Routes
app.use('/api', authRoutes);

// Server start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));