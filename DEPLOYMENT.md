# SecureDB: Complete Cloud & Production Deployment Guide

This guide walks you through deploying **SecureDB** to the cloud so anyone (including professors, examiners, and project evaluators) can access it via a live public HTTPS link.

---

## 🌟 Recommended Deployment Options at a Glance

| Method | Cost | Best For | Setup Time | Public HTTPS URL |
| :--- | :--- | :--- | :--- | :--- |
| **Option 1: Render.com** *(Recommended)* | **Free** | College review, viva, permanent portfolio | ~5 minutes | `https://securedb-xxxx.onrender.com` |
| **Option 2: Railway.app** | Free trial / \$5 | Dockerfile auto-deploy, zero config | ~3 minutes | `https://securedb.up.railway.app` |
| **Option 3: Cloud VPS (AWS / DigitalOcean / Oracle)** | \$4-6 / Free tier | Full multi-container Docker Compose with live target DB | ~10 minutes | `https://your-domain-or-ip` |
| **Option 4: Instant Public Live URL** | **Free** | Presenting right now from your laptop | **30 seconds** | `https://xxxx.loca.lt` |

---

## 🚀 Option 1: Render.com (Recommended Free Deployment)

Render allows you to deploy Docker containers directly from your GitHub repository (`immanya/securedb`) for free.

### Step-by-Step Instructions:

1. **Push the latest deployment files to GitHub**:
   Open a terminal in your project folder (`C:\Users\DELL\OneDrive\Desktop\SecureDB`) and push the changes:
   ```bash
   git add .
   git commit -m "Add cloud deployment configuration for Render and Railway"
   git push origin main
   ```

2. **Sign in to Render**:
   - Go to [https://render.com](https://render.com) and log in with your GitHub account.

3. **Deploy using the Blueprint (`render.yaml`)**:
   - On the Render Dashboard, click **New +** ➔ **Blueprint**.
   - Select your repository: **`immanya/securedb`**.
   - Render will automatically read `render.yaml` from your repository and configure:
     - **Web Service**: SecureDB (built using the multi-stage `Dockerfile`).
     - **PostgreSQL Database**: Free managed PostgreSQL database (`securedb-postgres`).
     - **Environment Variables**: Auto-generates `SECUREDB_MASTER_KEY` and `JWT_SECRET_KEY`.
   - Click **Apply**.

4. **Wait for Build & Launch**:
   - Render will build the React frontend and Python backend, run health checks against `/api/health`, and publish your app.
   - Your live public URL will be displayed at the top:
     `https://securedb-xxxx.onrender.com`

---

## 🚆 Option 2: Railway.app (1-Click Deploy)

Railway provides one of the fastest container deployment workflows with native Dockerfile support.

### Step-by-Step Instructions:

1. Go to [https://railway.app](https://railway.app) and log in with GitHub.
2. Click **New Project** ➔ **Deploy from GitHub repo**.
3. Select **`immanya/securedb`**.
4. Railway will automatically detect `railway.json` and build the `Dockerfile`.
5. *(Optional)* To attach a managed PostgreSQL database:
   - In your Railway project canvas, click **+ New** ➔ **Database** ➔ **Add PostgreSQL**.
   - Railway will automatically link `DATABASE_URL` to your SecureDB service.
6. Under **Variables**, add:
   - `SECUREDB_MASTER_KEY`: (Run `python -c "import secrets; print(secrets.token_hex(32))"` to generate a 64-character hex string)
   - `JWT_SECRET_KEY`: `any-random-long-secret-key-string`
7. Under **Settings** ➔ **Networking**, click **Generate Domain**.
   - Your app will be live at `https://securedb-production.up.railway.app`.

---

## ☁️ Option 3: Cloud VPS (AWS EC2, DigitalOcean, or Oracle Cloud)

If you have a Linux VM (Ubuntu/Debian), you can run the entire 3-container stack (`app`, `app_db`, and the sample `collegedb` target database) using Docker Compose.

### Step-by-Step Instructions:

1. **Connect to your server via SSH**:
   ```bash
   ssh ubuntu@your-server-ip
   ```

2. **Install Docker and Docker Compose**:
   ```bash
   sudo apt update && sudo apt install -y docker.io docker-compose-v2 git
   sudo usermod -aG docker $USER
   newgrp docker
   ```

3. **Clone your repository**:
   ```bash
   git clone https://github.com/immanya/securedb.git
   cd securedb
   ```

4. **Set up environment variables**:
   ```bash
   cp .env.example .env
   # Generate a 256-bit master key and put it into .env:
   MASTER_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
   sed -i "s/REPLACE_WITH_64_HEX_CHARS/$MASTER_KEY/" .env
   sed -i "s/REPLACE_WITH_RANDOM_SECRET/$(python3 -c 'import secrets; print(secrets.token_hex(24))')/" .env
   ```

5. **Start all services**:
   ```bash
   docker compose up --build -d
   ```

6. **Verify the services are running**:
   ```bash
   docker compose ps
   curl http://localhost:8000/api/health
   ```
   Your app will be accessible at `http://your-server-ip:8000/`.

---

## ⚡ Option 4: Instant Public Live URL (For Viva / Demo Right Now)

If you need a public URL **right now** to show your professors from their phones or laptops without setting up cloud accounts:

1. **Start the local server**:
   Double-click `START_SECUREDB.bat` on your Desktop (or run `python -m uvicorn app.main:app --port 8000`).

2. **Open a new terminal and run**:
   ```powershell
   npx localtunnel --port 8000
   ```
   Or using Cloudflare Tunnel:
   ```powershell
   winget install Cloudflare.cloudflared
   cloudflared tunnel --url http://localhost:8000
   ```

3. You will immediately get a public HTTPS URL (e.g. `https://lucky-tiger-42.loca.lt` or `https://xxxx.trycloudflare.com`). Anyone in the room can open it on their mobile phone or laptop and interact with your dashboard in real time!

---

## 🔑 Key Production Environment Variables Reference

| Variable | Description | Example / Default |
| :--- | :--- | :--- |
| `SECUREDB_MASTER_KEY` | 256-bit hexadecimal master key for envelope encryption | 64 hex characters (e.g., `0123...cdef`) |
| `DATABASE_URL` | PostgreSQL or SQLite connection string | `postgresql://user:pass@host:5432/dbname` |
| `JWT_SECRET_KEY` | Secret key for signing 15-minute JWT access tokens | Random 32+ character string |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Access token expiration window | `15` |
| `SECUREDB_STORAGE_DIR` | Directory where encrypted `.secdb` archives are stored | `/app/storage/backups` |
| `SECUREDB_TEMP_DIR` | Scratch directory for temporary dumps before encryption | `/app/storage/temp` |
