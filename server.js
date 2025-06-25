const express = require('express');
const app = express();

// Use image store routes
app.use('/images', require('./routes/imageStore'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});