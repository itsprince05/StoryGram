# API Documentation

---

## 1. Home Feed

```bash
curl -X GET "https://storygram-bgff.onrender.com/home" \
  -H "language: hindi" \
  -H "api-type: explore_v2"
```

```json
{
  "status": 1,
  "message": "Home feed details",
  "result": [
    {
      "module_name": "Trending Audio Series",
      "entities": [
        {
          "show_id": "show_12345abcdef",
          "title": "Sample Audio Series | नमूना धारावाहिक",
          "image": "https://example.com/images/show_cover.webp",
          "rank": 1,
          "plays": 1500000000,
          "rating": 4.8
        }
      ]
    }
  ]
}
```

---

## 2. Search

```bash
curl -X GET "https://storygram-bgff.onrender.com/search" \
  -H "query: Sample" \
  -H "language: hindi"
```

```json
{
  "status": 1,
  "message": "successfully fetched shows",
  "result": {
    "shows": [
      {
        "show_id": "show_12345abcdef",
        "title": "Sample Audio Series | नमूना धारावाहिक",
        "image": "https://example.com/images/show_cover.webp",
        "rank": 1,
        "plays": 1500000000,
        "rating": 4.8
      }
    ]
  }
}
```

---

## 3. Show Details & Episodes

```bash
curl -X GET "https://storygram-bgff.onrender.com/show" \
  -H "show-id: show_12345abcdef" \
  -H "curr-ptr: 0"
```

```json
{
  "status": 1,
  "message": "Result for show details page",
  "result": [
    {
      "show_id": "show_12345abcdef",
      "title": "Sample Audio Series | नमूना धारावाहिक",
      "image": "https://example.com/images/show_cover.webp",
      "rank": 1,
      "plays": 1500000000,
      "rating": 4.8,
      "episodes": 100,
      "stories": [
        {
          "duration": 600.0,
          "sequence": 1,
          "story_id": "story_001_abc123",
          "story_title": "Ep 1 - The Beginning",
          "video_url": "https://example.com/hls/ep1/master.m3u8",
          "audio_url": null,
          "media_url": "https://example.com/drm-aac/<show_id>/<story_id>/h264.mpd"
        }
      ]
    }
  ]
}
```

---

## 4. Widevine License URL

```bash
curl -X GET "https://storygram-bgff.onrender.com/license" \
  -H "show-id: show_12345abcdef"
```

```json
{
  "status": 1,
  "success": true,
  "message": "License server",
  "license_url": "https://<widevine-license-server>/..."
}
```

---

## 5. Widevine License Proxy

```bash
curl -X POST "https://storygram-bgff.onrender.com/widevine-license" \
  -H "Content-Type: application/octet-stream" \
  -H "show-id: show_12345abcdef" \
  --data-binary @challenge.bin \
  --output license.bin
```

```
200 OK (raw license bytes)
```

---

## 6. Health Check

```bash
curl -X GET "https://storygram-bgff.onrender.com/health"
```

```json
{
  "status": "online",
  "service": "running"
}
```
