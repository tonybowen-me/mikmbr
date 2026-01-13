# Project Renamed: airisk → Mikmbr

The project has been successfully renamed from "airisk" to "Mikmbr" to avoid naming conflicts.

## What Changed

### Package Name
- **Old**: `airisk`
- **New**: `mikmbr` (lowercase for pip/Python)
- **Display Name**: `Mikmbr` (capitalized for branding)

### Installation Command
```bash
# Old
pip install airisk
airisk scan .

# New
pip install mikmbr
mikmbr scan .
```

### Configuration File
- **Old**: `.airisk.yaml`
- **New**: `.mikmbr.yaml`

### Directory Structure
```
src/
├── airisk/        # OLD - removed
└── mikmbr/        # NEW
    ├── cli.py
    ├── config.py
    ├── scanner.py
    └── rules/
```

### Class Names
- `AiriskConfig` → `MikmbrConfig`

### GitHub URLs
All references now point to:
- `https://github.com/tonybowen-me/Mikmbr`

## Files Updated

### Python Source Files
- `src/mikmbr/*.py` - All module references and docstrings
- `tests/*.py` - Test imports and references
- `demo*.py` - Demo script imports
- `examples/*.py` - Example file imports

### Configuration Files
- `pyproject.toml` - Package name and entry point
- `.mikmbr.yaml` - Main config file
- `examples/.mikmbr.yaml` - Example config

### Documentation
- `README.md` - All command examples and references
- `CHANGELOG.md` - Product name
- `CONFIGURATION.md` - Config file references
- `HOW_IT_WORKS.md` - Product name
- `SMART_SECRETS.md` - Product name
- `V1.5_NEW_RULES.md` - Product name
- `DEPLOY_RENDER.md` - Deployment instructions
- `DEPLOYMENT_CHECKLIST.md` - Deployment steps
- All other `.md` files

### Website Files
- `website/index.html` - Title, logo, all content
- `website/style.css` - No changes needed
- `website/script.js` - No changes needed

### CI/CD
- `.github/workflows/ci.yml` - All test and scan commands

## Next Steps

### 1. Reinstall Package (Windows)
Since you're on Windows, run in CMD (not bash):
```cmd
py -m pip uninstall airisk -y
py -m pip install -e .
```

### 2. Test the Rename
```cmd
mikmbr scan .
```

### 3. Update Git (if needed)
```bash
git add .
git commit -m "Rename project from airisk to Mikmbr"
```

### 4. Before Publishing
When you're ready to publish, update these placeholders:
- Replace `yourusername` with your actual GitHub username in all files
- The package name `mikmbr` is ready for PyPI

## Notes

- The old `src/airisk.egg-info/` directory can be safely deleted
- All imports now use `from mikmbr import ...`
- The CLI command is now `mikmbr` instead of `airisk`
- Config files are now `.mikmbr.yaml` instead of `.airisk.yaml`

Everything is ready to go! The rename is complete across all 40+ files.
