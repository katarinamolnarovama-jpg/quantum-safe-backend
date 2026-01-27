# Quantum-Safe Backend v2.0 - With Database Support

## What's New
- ✅ PostgreSQL database integration
- ✅ Persistent document storage
- ✅ Compliance tracking in database
- ✅ Audit trail logging
- ✅ Automatic schema initialization

## Deployment Instructions

### Step 1: Update Files on Render
1. Go to your GitHub repository: `quantum-safe-backend`
2. Replace `main.py` and `requirements.txt` with the new versions
3. Commit the changes

### Step 2: Add Database Environment Variable
1. Go to Render.com → Your Web Service (`quantum-safe-api`)
2. Click "Environment" in the left sidebar
3. Click "Add Environment Variable"
4. Add:
   - **Key:** `DATABASE_URL`
   - **Value:** `postgresql://pqc_law_tool_user:lkIunqamnfmQhApnXwtHZbOeRcroaOhy@dpg-d5skevvgi27c73cc06tg-a/pqc_law_tool`
5. Click "Save Changes"

### Step 3: Redeploy
Render will automatically redeploy your service with database support!

## Features
- Document encryption with AES-256-GCM
- Database-backed storage
- Compliance framework tracking (9 frameworks)
- Audit trail logging
- Automatic fallback to file storage if database unavailable

## API Endpoints
- `GET /api/v1/health` - Health check with database status
- `POST /api/v1/encrypt` - Encrypt and store documents
- `GET /api/v1/document/{id}` - Download encrypted document
- `GET /api/v1/document/{id}/info` - Get document metadata
- `GET /api/v1/audit-trail` - Get recent audit events
- `GET /api/v1/compliance/summary` - Get compliance summary

## Database Schema
Tables automatically created on startup:
- `users` - User accounts
- `documents` - Document records
- `compliance_records` - Compliance framework tracking
- `audit_trail` - Action logging

## Version
2.0.0 - Database Integration
