# Deploying mikmbr Website to Render

This guide will help you deploy the mikmbr landing page to Render with your custom domain (mikmbr.io).

## Prerequisites

- GitHub account with this repository pushed
- Render account (render.com)
- Domain: mikmbr.io

## Step 1: Push to GitHub

Make sure all website files are committed and pushed:

```bash
git add .
git commit -m "Add mikmbr website"
git push origin main
```

## Step 2: Create Static Site on Render

1. Log in to [Render Dashboard](https://dashboard.render.com/)
2. Click **"New +"** → **"Static Site"**
3. Connect your GitHub repository
4. Configure the static site:

   - **Name**: `mikmbr` (or your preferred name)
   - **Branch**: `main`
   - **Root Directory**: `website`
   - **Build Command**: Leave blank (no build needed for static HTML)
   - **Publish Directory**: `.` (current directory since we're already in website/)

5. Click **"Create Static Site"**

## Step 3: Configure Custom Domain

After deployment completes:

1. Go to your static site's **Settings** in Render
2. Scroll to **"Custom Domains"**
3. Click **"Add Custom Domain"**
4. Enter: `mikmbr.io` (and optionally `www.mikmbr.io`)
5. Render will provide DNS records to configure

## Step 4: Configure DNS at Your Domain Registrar

Go to your domain registrar (where you bought mikmbr.io) and add these DNS records:

### For root domain (mikmbr.io):
- **Type**: `CNAME` or `ALIAS` (use ALIAS if available, otherwise CNAME)
- **Name**: `@` or leave blank
- **Value**: `[your-site-name].onrender.com` (Render will show you this)

### For www subdomain (www.mikmbr.io):
- **Type**: `CNAME`
- **Name**: `www`
- **Value**: `[your-site-name].onrender.com`

**Note**: DNS propagation can take 5 minutes to 48 hours.

## Step 5: Enable HTTPS

Once DNS is configured:

1. Return to Render dashboard
2. Go to your site's **Settings**
3. Under **"Custom Domains"**, wait for SSL certificate status to show "Verified"
4. Render automatically provisions Let's Encrypt SSL certificates
5. Enable **"Force HTTPS"** in settings

## Alternative: Quick Deploy (No Custom Domain)

If you just want to test quickly without custom domain:

1. Follow Step 1-2 above
2. Skip Steps 3-5
3. Your site will be available at: `https://[your-site-name].onrender.com`

## File Structure

Your website files should be organized like this:

```
website/
├── index.html       (Main landing page)
├── style.css        (Styles)
└── script.js        (JavaScript functionality)
```

## Updating the Website

To make updates:

1. Edit files locally
2. Commit changes: `git add . && git commit -m "Update website"`
3. Push to GitHub: `git push origin main`
4. Render automatically redeploys (takes ~1 minute)

## Troubleshooting

### Site not loading
- Check that "Publish Directory" is set to `.` (not `website/`)
- Verify `index.html` exists in the website folder
- Check Render deployment logs for errors

### Custom domain not working
- Verify DNS records are correct using: `dig mikmbr.io` or `nslookup mikmbr.io`
- Wait for DNS propagation (can take up to 48 hours)
- Check Render's "Custom Domains" section for verification status

### CSS/JS not loading
- Check that file paths in index.html are correct: `href="style.css"` (not `href="/style.css"`)
- Clear browser cache (Ctrl+Shift+R or Cmd+Shift+R)
- Check browser console for 404 errors

## Production Checklist

Before going live, verify:

- [ ] All GitHub URLs updated to your actual repository
- [ ] Twitter/social links updated to your accounts
- [ ] Analytics added (Google Analytics, Plausible, etc.) if desired
- [ ] SEO metadata reviewed in index.html
- [ ] Test all navigation links work
- [ ] Test mobile responsive design
- [ ] HTTPS enabled and working
- [ ] Custom domain configured correctly

## Next Steps

After deployment:

1. **Update GitHub URLs**: Replace all `https://github.com/tonybowen-me/Mikmbr` with your actual repository URL
2. **Add Analytics**: Insert tracking code if you want visitor analytics
3. **Submit to Search Engines**:
   - Google Search Console
   - Bing Webmaster Tools
4. **Share**:
   - Post on Twitter, Reddit (r/Python, r/netsec)
   - Submit to ShowHN on Hacker News
   - Add to security tool directories

## Cost

Render's static sites are **FREE** for:
- 100 GB bandwidth/month
- Unlimited sites
- Automatic SSL certificates
- Custom domains
- Automatic deploys from Git

Perfect for a landing page like this!
