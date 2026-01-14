# Deployment Checklist for mikmbr

Use this checklist before deploying to production (hookcrate.io).

## Pre-Deployment Tasks

### 1. Update GitHub URLs
- [ ] Replace all `https://github.com/tonybowen-me/Mikmbr` in website/index.html
- [ ] Replace all `https://github.com/tonybowen-me/Mikmbr` in README.md
- [ ] Update footer links in website/index.html

### 2. Update Social Links
- [ ] Twitter link in website/index.html footer (line 295)
- [ ] Add your actual Twitter/social media handles

### 3. Repository Setup
- [ ] Push all code to GitHub
- [ ] Verify repository is public (or change links to private repo if needed)
- [ ] Add repository description and topics on GitHub

### 4. Documentation Review
- [ ] README.md has correct installation instructions
- [ ] All example code snippets work
- [ ] Links to documentation files work
- [ ] Version numbers are consistent (currently 1.5.0)

## Website Deployment to Render

### 5. Deploy to Render
- [ ] Log in to Render dashboard
- [ ] Create new Static Site
- [ ] Connect GitHub repository
- [ ] Set Root Directory to `website`
- [ ] Set Publish Directory to `.`
- [ ] Deploy and verify

### 6. Custom Domain Setup
- [ ] Add custom domain `mikmbr.io` in Render
- [ ] Configure DNS records at domain registrar:
  - CNAME/ALIAS for `@` → `your-site.onrender.com`
  - CNAME for `www` → `your-site.onrender.com`
- [ ] Wait for DNS propagation (5 mins - 48 hours)
- [ ] Verify SSL certificate is provisioned
- [ ] Enable "Force HTTPS" in Render settings

## Post-Deployment Tasks

### 7. Test Website
- [ ] Visit mikmbr.io (or your Render URL)
- [ ] Test all navigation links work
- [ ] Test mobile responsive design
- [ ] Verify CSS and JavaScript load correctly
- [ ] Check browser console for errors
- [ ] Test on multiple browsers (Chrome, Firefox, Safari)

### 8. SEO and Analytics (Optional)
- [ ] Add Google Analytics or Plausible tracking code
- [ ] Submit to Google Search Console
- [ ] Submit to Bing Webmaster Tools
- [ ] Create sitemap.xml if desired

### 9. Marketing and Outreach
- [ ] Post on Twitter announcing the release
- [ ] Submit to Show HN on Hacker News
- [ ] Post on r/Python subreddit
- [ ] Post on r/netsec subreddit
- [ ] Add to Awesome Python lists
- [ ] Add to security tools directories

## Package Publishing (Optional - PyPI)

If you want to publish to PyPI so users can `pip install mikmbr`:

### 10. PyPI Setup
- [ ] Create account on [PyPI.org](https://pypi.org)
- [ ] Create account on [TestPyPI.org](https://test.pypi.org) for testing
- [ ] Install build tools: `pip install build twine`

### 11. Build Package
```bash
python -m build
```
- [ ] Verify dist/ folder created with .tar.gz and .whl files

### 12. Test on TestPyPI
```bash
python -m twine upload --repository testpypi dist/*
```
- [ ] Verify package appears on TestPyPI
- [ ] Test installation: `pip install -i https://test.pypi.org/simple/ mikmbr`

### 13. Upload to Real PyPI
```bash
python -m twine upload dist/*
```
- [ ] Verify package on [PyPI.org/project/mikmbr](https://pypi.org/project/mikmbr)
- [ ] Test installation: `pip install mikmbr`
- [ ] Update website installation instructions if needed

## Final Verification

### 14. End-to-End Test
- [ ] Fresh clone of repository works
- [ ] Installation from PyPI works (if published)
- [ ] `mikmbr scan .` works on a test project
- [ ] Website loads correctly at mikmbr.io
- [ ] All documentation links work
- [ ] CI/CD pipeline passes on GitHub Actions

## Maintenance

### 15. Ongoing Tasks
- [ ] Monitor GitHub issues
- [ ] Respond to pull requests
- [ ] Update CHANGELOG.md for new releases
- [ ] Keep dependencies updated
- [ ] Monitor website uptime

---

## Quick Commands

### Test Installation Locally
```bash
pip install -e .
mikmbr scan examples/
```

### Build for PyPI
```bash
python -m build
python -m twine check dist/*
```

### Update Version (for future releases)
1. Update version in `pyproject.toml`
2. Update version in `CHANGELOG.md`
3. Commit: `git commit -am "Bump version to X.Y.Z"`
4. Tag: `git tag vX.Y.Z`
5. Push: `git push && git push --tags`
6. Build and upload to PyPI

---

**Note**: This checklist assumes you're deploying v1.5.0. Adjust version numbers as needed for future releases.
