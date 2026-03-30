const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs-extra');
const multer = require('multer');
const AdmZip = require('adm-zip');

const app = express();
const PORT = process.env.PORT || 3000;

const REGISTRY_FILE = path.join(__dirname, 'registry.json');
const CDN_DIR = path.join(__dirname, 'cdn');
const PUBLIC_DIR = path.join(__dirname, 'public');
const UPLOAD_DIR = path.join(__dirname, 'temp');

// Ensure directories exist
[CDN_DIR, PUBLIC_DIR, UPLOAD_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) {
    console.log(`📁 Creating directory: ${path.basename(dir)}`);
    fs.ensureDirSync(dir);
  }
});

// Initialize registry if not exists
if (!fs.existsSync(REGISTRY_FILE)) {
  console.log(`📄 Initializing registry: ${path.basename(REGISTRY_FILE)}`);
  fs.writeJsonSync(REGISTRY_FILE, []);
}

app.use(cors());
app.use(express.json());
app.use('/cdn', express.static(CDN_DIR));
app.use(express.static(PUBLIC_DIR));

const upload = multer({ dest: UPLOAD_DIR });

// HELPER: Read Registry
const getRegistry = () => fs.readJsonSync(REGISTRY_FILE);
const saveRegistry = (data) => fs.writeJsonSync(REGISTRY_FILE, data, { spaces: 2 });

/** 
 * CONSUMER API: Get Active Modules
 * Consumers call this to know which modules to load.
 */
app.get('/modules', (req, res) => {
  const registry = getRegistry();
  const host = `${req.protocol}://${req.get('host')}`;
  
  const modules = registry.map(a => {
    const devPath = path.join(CDN_DIR, a.id, 'dev', 'index.bundle');
    const hasDev = fs.existsSync(devPath);

    return {
      id: a.id,
      name: a.name,
      active_version: a.active_version,
      active_version_url: a.active_version 
        ? `${host}/cdn/${a.id}/${a.active_version}/index.bundle`
        : null,
      dev_url: hasDev 
        ? `${host}/cdn/${a.id}/dev/index.bundle`
        : null
    };
  });
  
  res.json(modules);
});

app.get('/api/admin/modules', (req, res) => {
  const host = req.get('host');
  const protocol = req.headers['x-forwarded-proto'] || req.protocol;
  const baseUrl = `${protocol}://${host}`;
  
  const registry = getRegistry();
  const modules = registry.map(a => {
    const devPath = path.join(CDN_DIR, a.id, 'dev', 'index.bundle');
    const hasDev = fs.existsSync(devPath);
    
    let last_dev_update = null;
    if (hasDev) {
      last_dev_update = fs.statSync(devPath).mtime;
    }

    let last_prod_update = null;
    if (a.active_version) {
      const prodPath = path.join(CDN_DIR, a.id, a.active_version, 'index.bundle');
      if (fs.existsSync(prodPath)) {
        last_prod_update = fs.statSync(prodPath).mtime;
      }
    }

    return {
      ...a,
      has_dev_bundle: hasDev,
      dev_url: hasDev ? `${baseUrl}/cdn/${a.id}/dev/index.bundle` : null,
      last_dev_update,
      last_prod_update
    };
  });
  res.json(modules);
});

/**
 * ADMIN API: Create Module
 */
app.post('/api/admin/modules', (req, res) => {
  const { id, name, description } = req.body;
  const registry = getRegistry();
  
  if (registry.find(a => a.id === id)) {
    return res.status(400).json({ error: 'Module already exists' });
  }

  const newAsset = {
    id,
    name,
    description,
    active_version: null,
    is_dev_mode: false,
    dev_url: null,
    versions: []
  };

  registry.push(newAsset);
  saveRegistry(registry);
  res.status(201).json(newAsset);
});

/**
 * ADMIN API: Update Module (Dev Mode toggles)
 */
app.put('/api/admin/modules/:id', (req, res) => {
  const { id } = req.params;
  const registry = getRegistry();
  const index = registry.findIndex(a => a.id === id);
  
  if (index === -1) return res.status(404).json({ error: 'Not found' });

  registry[index] = { ...registry[index], ...req.body };
  saveRegistry(registry);
  res.json(registry[index]);
});

/**
 * ADMIN API: Delete Module
 */
app.delete('/api/admin/modules/:id', (req, res) => {
  const { id } = req.params;
  const registry = getRegistry();
  const filteredRegistry = registry.filter(a => a.id !== id);
  
  if (registry.length === filteredRegistry.length) {
    return res.status(404).json({ error: 'Module not found' });
  }

  saveRegistry(filteredRegistry);
  
  // Optionally delete files
  const assetDir = path.join(CDN_DIR, id);
  if (fs.existsSync(assetDir)) {
    fs.removeSync(assetDir);
  }

  res.status(204).end();
});

/**
 * ADMIN API: Upload Development Bundle (Cloud-Dev Sync)
 * Overwrites the single development slot for the module.
 */
app.post('/api/admin/modules/:id/dev', upload.single('bundle'), (req, res) => {
  const { id } = req.params;
  
  if (!req.file) {
    return res.status(400).json({ error: 'Missing bundle file' });
  }

  const registry = getRegistry();
  const index = registry.findIndex(a => a.id === id);
  if (index === -1) return res.status(404).json({ error: 'Module not found' });

  try {
    const devPath = path.join(CDN_DIR, id, 'dev');
    
    // ATOMIC REPLACE: Clean previous dev files
    if (fs.existsSync(devPath)) {
      fs.removeSync(devPath);
    }
    fs.ensureDirSync(devPath);
    
    const zip = new AdmZip(req.file.path);
    zip.extractAllTo(devPath, true);
    
    // Cleanup temp file
    fs.unlinkSync(req.file.path);
    
    console.log(`☁️  Dev-Cloud Sync: ${id} updated.`);
    res.json({ message: 'Dev bundle updated', id });
  } catch (err) {
    res.status(500).json({ error: 'Failed to process dev bundle: ' + err.message });
  }
});

/**
 * ADMIN API: Upload Bundle Version
 */
app.post('/api/admin/modules/:id/versions', upload.single('bundle'), (req, res) => {
  const { id } = req.params;
  const { version } = req.body;
  
  if (!req.file || !version) {
    return res.status(400).json({ error: 'Missing bundle file or version' });
  }

  const registry = getRegistry();
  const index = registry.findIndex(a => a.id === id);
  if (index === -1) return res.status(404).json({ error: 'Asset not found' });

  try {
    const extractPath = path.join(CDN_DIR, id, version);
    fs.ensureDirSync(extractPath);
    
    const zip = new AdmZip(req.file.path);
    zip.extractAllTo(extractPath, true);
    
    // Update registry
    if (!registry[index].versions.includes(version)) {
      registry[index].versions.push(version);
    }
    registry[index].active_version = version;
    saveRegistry(registry);

    // Cleanup temp file
    fs.unlinkSync(req.file.path);
    
    res.json(registry[index]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to process bundle: ' + err.message });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Simple CDN running on http://localhost:${PORT}`);
});
