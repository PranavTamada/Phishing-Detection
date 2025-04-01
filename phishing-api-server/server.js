import cors from 'cors';
import express from 'express';
import fetch from 'node-fetch';

const app = express();
const PORT = 5001;

app.use(cors()); // Enable CORS

app.get("/fetch-phishing-data", async (req, res) => {
    try {
        const response = await fetch("https://openphish.com/feed.txt");
        if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);

        const text = await response.text();
        res.send(text); // Send data to the extension
    } catch (error) {
        console.error("Error fetching phishing data:", error);
        res.status(500).json({ error: "Failed to fetch data" });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
