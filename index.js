const express = require('express')
const app = express();
const port = 8032;

app.get('/', (req, res) => {
    res.send('Server is running on port 8032');
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});