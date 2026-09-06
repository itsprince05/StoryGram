const express = require('express');
const axios = require('axios');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = 'https://api.pocketfm.com';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/**
 * Helper function to construct Pocket FM headers dynamically.
 * Client only needs to send 'authorization' (or 'auth') and optionally 'language'.
 * All other required device/platform headers are automatically attached.
 */
function buildPocketHeaders(req) {
  // Extract Authorization token
  let token = req.headers['authorization'] || req.headers['auth'] || req.headers['x-auth-token'] || process.env.DEFAULT_BEARER_TOKEN || '';
  
  if (token && !token.toLowerCase().startsWith('bearer ')) {
    token = `Bearer ${token.trim()}`;
  }

  // Extract language from header, or query param, or default to hindi
  const language = req.headers['language'] || req.query.language || req.query.selected_language || 'hindi';

  return {
    'Host': 'api.pocketfm.com',
    'app-name': 'pocket_fm',
    'content-type': 'application/json;charset=utf-8',
    'accept': 'application/json',
    'version-name': '9.1.3',
    'platform-version': '29',
    'app-version': '2013',
    'language': language,
    'authorization': token,
    'User-Agent': 'okhttp/4.9.2'
  };
}

/**
 * Common request dispatcher for Pocket FM
 */
async function forwardToPocketFM(targetUrl, req, res) {
  try {
    const headers = buildPocketHeaders(req);

    if (!headers.authorization || headers.authorization === 'Bearer ') {
      return res.status(401).json({
        success: false,
        error: "Missing Authorization token. Please pass 'authorization' or 'auth' in headers."
      });
    }

    const response = await axios({
      method: req.method,
      url: targetUrl,
      headers: headers,
      params: req.query,
      data: req.method !== 'GET' ? req.body : undefined,
      timeout: 15000,
      validateStatus: () => true // Allow handling non-200 responses smoothly
    });

    return res.status(response.status).json(response.data);
  } catch (error) {
    console.error(`[Proxy Error] ${req.method} ${targetUrl} ->`, error.message);
    return res.status(error.response?.status || 500).json({
      success: false,
      message: 'Failed to fetch from Pocket FM API',
      error: error.message,
      details: error.response?.data || null
    });
  }
}

// -------------------------------------------------------------
// 1. Health / Keep-Alive Endpoint (For 1-min Cron Job)
// -------------------------------------------------------------
app.get(['/health', '/ping'], (req, res) => {
  res.status(200).json({
    status: 'online',
    message: 'Pocket FM API Proxy is awake and running',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// -------------------------------------------------------------
// 2. Feed Data Endpoint (Explore / Feed)
// Example: GET /api/feed?api_type=explore_v2&selected_language=hindi
// -------------------------------------------------------------
app.get('/api/feed', (req, res) => {
  const language = req.headers['language'] || req.query.selected_language || req.query.language || 'hindi';
  const apiType = req.query.api_type || 'explore_v2';
  
  const queryParams = new URLSearchParams({
    api_type: apiType,
    selected_language: language,
    ...req.query
  }).toString();

  const url = `${BASE_URL}/v2/feed_api/get_feed_data?${queryParams}`;
  return forwardToPocketFM(url, req, res);
});

// -------------------------------------------------------------
// 3. Universal Search Endpoint
// Example: GET /api/search?query=insta%20millionaire&genre=
// -------------------------------------------------------------
app.get('/api/search', (req, res) => {
  const query = req.query.query || req.query.q || '';
  const genre = req.query.genre || '';

  const queryParams = new URLSearchParams({
    query: query,
    genre: genre,
    ...req.query
  }).toString();

  const url = `${BASE_URL}/v3/search/universal.search?${queryParams}`;
  return forwardToPocketFM(url, req, res);
});

// -------------------------------------------------------------
// 4. Show Details Endpoint
// Example 1: GET /api/show?show_id=4befca3da259b11359969ac8d4813650c587b440&curr_ptr=100
// Example 2: GET /api/show/4befca3da259b11359969ac8d4813650c587b440
// -------------------------------------------------------------
app.get(['/api/show', '/api/show/:show_id'], (req, res) => {
  const showId = req.params.show_id || req.query.show_id;
  
  if (!showId) {
    return res.status(400).json({
      success: false,
      error: "Missing 'show_id'. Pass it as path param (/api/show/:id) or query param (?show_id=...)"
    });
  }

  const queryParams = new URLSearchParams({
    show_id: showId,
    curr_ptr: req.query.curr_ptr || '100',
    info_level: req.query.info_level || '100',
    page_source: req.query.page_source || 'show_detail',
    ...req.query
  }).toString();

  const url = `${BASE_URL}/v2/content_api/show.get_details?${queryParams}`;
  return forwardToPocketFM(url, req, res);
});

// -------------------------------------------------------------
// 5. Universal Dynamic Proxy (Hit ANY Pocket FM Endpoint)
// Example: GET /api/proxy/v2/content_api/episode.get_details?episode_id=...
// -------------------------------------------------------------
app.all('/api/proxy/*', (req, res) => {
  const endpointPath = req.params[0]; // captures everything after /api/proxy/
  const queryParams = new URLSearchParams(req.query).toString();
  const url = `${BASE_URL}/${endpointPath}${queryParams ? `?${queryParams}` : ''}`;
  return forwardToPocketFM(url, req, res);
});

// -------------------------------------------------------------
// 6. Home / Interactive Documentation Dashboard
// -------------------------------------------------------------
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Pocket FM API Proxy</title>
      <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
      <style>
        :root {
          --bg: #090d16;
          --card: #131b2e;
          --accent: #f97316;
          --accent-glow: rgba(249, 115, 22, 0.25);
          --text: #f1f5f9;
          --muted: #94a3b8;
          --border: #243049;
          --code-bg: #0d1322;
          --success: #10b981;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
          font-family: 'Outfit', sans-serif;
          background-color: var(--bg);
          color: var(--text);
          padding: 2.5rem 1rem;
          display: flex;
          justify-content: center;
        }
        .container {
          max-width: 900px;
          width: 100%;
        }
        header {
          text-align: center;
          margin-bottom: 2.5rem;
        }
        .badge {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          background: rgba(16, 185, 129, 0.15);
          color: var(--success);
          padding: 6px 14px;
          border-radius: 9999px;
          font-size: 0.85rem;
          font-weight: 600;
          margin-bottom: 1rem;
          border: 1px solid rgba(16, 185, 129, 0.3);
        }
        .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--success); box-shadow: 0 0 8px var(--success); }
        h1 {
          font-size: 2.5rem;
          font-weight: 700;
          background: linear-gradient(135deg, #fff, #fb923c, #f97316);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          margin-bottom: 0.5rem;
        }
        p.subtitle {
          color: var(--muted);
          font-size: 1.05rem;
        }
        .card {
          background: var(--card);
          border: 1px solid var(--border);
          border-radius: 16px;
          padding: 1.75rem;
          margin-bottom: 1.5rem;
          box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }
        h2 {
          font-size: 1.3rem;
          margin-bottom: 1.25rem;
          display: flex;
          align-items: center;
          gap: 10px;
          color: #fff;
        }
        .endpoint {
          background: var(--code-bg);
          border: 1px solid var(--border);
          border-radius: 10px;
          padding: 1rem;
          margin-bottom: 1rem;
          font-family: 'JetBrains Mono', monospace;
          font-size: 0.9rem;
        }
        .endpoint-header {
          display: flex;
          align-items: center;
          gap: 10px;
          margin-bottom: 0.5rem;
        }
        .method {
          background: var(--accent);
          color: #fff;
          padding: 2px 8px;
          border-radius: 6px;
          font-size: 0.75rem;
          font-weight: 700;
        }
        .method.all {
          background: #8b5cf6;
        }
        .path { color: #38bdf8; font-weight: 600; }
        .desc {
          color: var(--muted);
          font-size: 0.85rem;
          font-family: 'Outfit', sans-serif;
          margin-top: 4px;
        }
        .headers-box {
          background: rgba(249, 115, 22, 0.08);
          border: 1px dashed rgba(249, 115, 22, 0.4);
          border-radius: 10px;
          padding: 1.2rem;
          margin-top: 1rem;
        }
        .headers-box h3 {
          font-size: 0.95rem;
          color: #fdba74;
          margin-bottom: 0.6rem;
        }
        ul {
          list-style: none;
          padding-left: 0;
        }
        li {
          padding: 4px 0;
          font-size: 0.9rem;
          color: var(--muted);
        }
        code {
          background: var(--code-bg);
          padding: 2px 6px;
          border-radius: 4px;
          color: #fca5a5;
          font-family: 'JetBrains Mono', monospace;
          font-size: 0.85rem;
        }
        .cron-box {
          background: rgba(56, 189, 248, 0.08);
          border: 1px solid rgba(56, 189, 248, 0.3);
          border-radius: 10px;
          padding: 1.2rem;
          margin-top: 1rem;
        }
        .cron-box h3 {
          color: #38bdf8;
          font-size: 0.95rem;
          margin-bottom: 0.5rem;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <header>
          <div class="badge"><span class="dot"></span> Server Active</div>
          <h1>Pocket FM API Proxy Server</h1>
          <p class="subtitle">High Performance • Dynamic Auth Forwarding • Anti-Sleep Keep Alive</p>
        </header>

        <div class="card">
          <h2>⚡ Ready Endpoints</h2>

          <div class="endpoint">
            <div class="endpoint-header">
              <span class="method">GET</span>
              <span class="path">/api/feed</span>
            </div>
            <div class="desc">Explore & feed list (Query params: <code>api_type=explore_v2</code>, <code>selected_language=hindi</code>)</div>
          </div>

          <div class="endpoint">
            <div class="endpoint-header">
              <span class="method">GET</span>
              <span class="path">/api/search</span>
            </div>
            <div class="desc">Universal search (Query params: <code>query=insta millionaire</code>, <code>genre=</code>)</div>
          </div>

          <div class="endpoint">
            <div class="endpoint-header">
              <span class="method">GET</span>
              <span class="path">/api/show/:show_id</span>
            </div>
            <div class="desc">Show details & episodes (e.g. <code>/api/show/4befca3da259b11359969ac8d4813650c587b440</code>)</div>
          </div>

          <div class="endpoint">
            <div class="endpoint-header">
              <span class="method all">ALL</span>
              <span class="path">/api/proxy/*</span>
            </div>
            <div class="desc">Dynamic proxy for ANY Pocket FM endpoint (e.g. <code>/api/proxy/v2/content_api/...</code>)</div>
          </div>

          <div class="endpoint">
            <div class="endpoint-header">
              <span class="method" style="background:#10b981;">GET</span>
              <span class="path">/health</span>
            </div>
            <div class="desc">Lightweight keep-alive ping for 1-minute Cron Jobs</div>
          </div>
        </div>

        <div class="card">
          <h2>🔑 Headers You Need to Pass</h2>
          <div class="headers-box">
            <h3>You only need to send:</h3>
            <ul>
              <li>• <code>authorization</code>: <code>Bearer eyJhbGci...</code> (or just <code>auth: eyJhbGci...</code>)</li>
              <li>• <code>language</code> (optional): <code>hindi</code>, <code>english</code>, etc. (Default is <code>hindi</code>)</li>
            </ul>
          </div>
          <p style="margin-top: 0.9rem; font-size: 0.85rem; color: var(--muted);">
            All fixed headers (<code>Host</code>, <code>app-name</code>, <code>version-name</code>, <code>platform-version</code>, <code>app-version</code>, <code>accept</code>, <code>content-type</code>) are automatically injected by this proxy server!
          </p>
        </div>

        <div class="card">
          <h2>⏱️ Cron Job Setup (Anti-Sleep)</h2>
          <div class="cron-box">
            <h3>Setup 1-min ping on your hosting / cron-job.org:</h3>
            <p style="font-size: 0.9rem; color: var(--muted); margin-bottom: 0.5rem;">Target URL:</p>
            <code>https://YOUR-APP-NAME.onrender.com/health</code>
          </div>
        </div>
      </div>
    </body>
    </html>
  `);
});

// Start Server
app.listen(PORT, () => {
  console.log(`=========================================`);
  console.log(`🚀 Pocket FM Proxy Server running on port ${PORT}`);
  console.log(`🌐 Base URL: http://localhost:${PORT}`);
  console.log(`💓 Keep-alive endpoint: http://localhost:${PORT}/health`);
  console.log(`=========================================`);
});
