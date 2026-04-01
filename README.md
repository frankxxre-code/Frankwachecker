# WA Checker Platform

Multi-user WhatsApp Number Verification Platform.

## Deploy to Railway

1. Push this folder to a GitHub repo
2. Railway → New Project → Deploy from GitHub
3. Set environment variables:

| Variable | Default | Description |
|---|---|---|
| `ADMIN_EMAIL` | `admin@wachecker.com` | Admin login email |
| `ADMIN_PASSWORD` | `Admin@2024!` | Admin login password |
| `SESSION_SECRET` | auto | Any random string |
| `PORT` | auto | Set by Railway |

4. Deploy — Railway builds and starts automatically

## Import Termux DB

Run in Termux:
```
cp ~/results_db.json ~/downloads/results_db.json
```
Then: Admin Panel → Import DB JSON → upload the file.
All existing results are available to all users immediately.

## Pages

- `/` → redirects to dashboard or login
- `/login.html` → login + register
- `/dashboard.html` → user dashboard
- `/admin.html` → admin only panel

## Features

### Users
- Register / login
- Add WhatsApp sessions (QR or pairing code)
- Upload files — any .txt or .csv format
- Check New (only uncached) or Check All (full recheck)
- Live progress via WebSocket
- Download results CSV
- Job history with resume

### Shared DB
- All users share the permanent results DB
- Cached numbers returned instantly to all users
- Admin can import/export the full DB

### Admin
- See all users, online status, active jobs
- Ban / unban / delete users
- View all jobs across all users
- Import Termux DB
- Export registered / not_registered CSV
