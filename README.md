# Quantum-Safe Encryption Backend - Render Deployment

## 🚀 Quick Deploy to Render.com

### Step 1: Upload to GitHub

1. Go to https://github.com/new
2. Create a new repository:
   - Name: `quantum-safe-backend`
   - Description: "Post-quantum encryption API"
   - Public or Private (your choice)
   - Click "Create repository"

3. Upload these files to your repository:
   - `main.py`
   - `requirements.txt`
   - `README.md`

### Step 2: Deploy on Render

1. Go to https://render.com
2. Sign up (free) or log in
3. Click "New +" → "Web Service"
4. Connect your GitHub account
5. Select your `quantum-safe-backend` repository
6. Configure:
   - **Name**: `quantum-safe-api` (or any name)
   - **Environment**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
   - **Instance Type**: Free
7. Click "Create Web Service"

### Step 3: Wait for Deployment (3-5 minutes)

Render will:
- Install dependencies
- Start your FastAPI server
- Give you a URL like: `https://quantum-safe-api-abc123.onrender.com`

### Step 4: Test Your API

Visit: `https://your-app-name.onrender.com/docs`

You should see the FastAPI documentation page!

### Step 5: Update Your HTML

In your `quantum-safe-app-v2.html`, change:

```javascript
const API_BASE = 'http://127.0.0.1:8000';
```

To:

```javascript
const API_BASE = 'https://your-app-name.onrender.com';
```

### Step 6: Upload HTML to GoDaddy

1. Log into GoDaddy cPanel
2. Go to File Manager
3. Navigate to `public_html/`
4. Upload your updated HTML file
5. Rename it to `index.html`

Done! 🎉

---

## 📝 Notes

- **Free tier sleeps after 15 min** of inactivity (wakes up in 30-60 sec)
- **Upgrade to $7/month** for always-on service
- **SSL/HTTPS included** automatically
- **Logs available** in Render dashboard

## 🔧 Troubleshooting

**If deployment fails:**
1. Check logs in Render dashboard
2. Verify `requirements.txt` matches this exactly
3. Ensure `main.py` doesn't have syntax errors

**If API doesn't work:**
1. Visit `https://your-url.onrender.com/api/v1/health`
2. Check if it returns JSON with status
3. Look at Render logs for errors

## 📧 Need Help?

Check Render documentation: https://render.com/docs
