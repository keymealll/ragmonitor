# Skerry travel site

The website of Skerry, a fictional travel app from Cork, used as the customer app that Cyber Tiger monitors. Its chat assistant runs through Cyber Tiger's chatbot API.

```bash
cp .env.example .env              # paste the token from: cd ../dashboard && python scripts/apptoken.py create "Skerry travel site"
uvicorn server:app --port 4000    # http://localhost:4000 (Cyber Tiger must be running on :8000)
```

- `server.py` serves `site/` and passes each chat question to `RAGMON_URL/v1/chat` with `Authorization: Bearer $RAGMON_TOKEN`. The token stays on this server; the browser only calls `/api/chat` here.
- `site/` is the page: built with the Hallmark Cobalt theme, no build step. The route map behind the hero is a canvas drawn from the six routes in Skerry's help centre.
- A rejected or missing token returns a plain message in the chat instead of an answer, so a broken connection is visible during the demo.
