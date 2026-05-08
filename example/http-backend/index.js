import express, { json } from 'express';
const app = express();

app.use(json());

app.get('/hello', (req, res) => {
    res.json({ message: 'Hello from Express backend!' });
});

app.post('/data', (req, res) => {
    res.json({
        received: req.body,
        info: 'Processed by Express backend'
    });
});

app.listen(3000, '127.0.0.1', () => {
    console.log('Express server running on http://127.0.0.1:3000');
});

