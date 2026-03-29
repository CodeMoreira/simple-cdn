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
 * CONSUMER API: Get Active Assets
 * Consumers call this to know which assets to load.
 */
app.get('/assets', (req, res) => {
  const registry = getRegistry();
  const activeAssets = registry
    .filter(a => (a.is_dev_mode && a.dev_url) || a.active_version) // FILTER: Must have dev_url or active_version
    .map(a => {
      let url = '';
      if (a.is_dev_mode && a.dev_url) {
        url = a.dev_url;
      } else if (a.active_version) {
        url = `${req.protocol}://${req.get('host')}/cdn/${a.id}/${a.active_version}/index.bundle`;
      }
      
      return {
        id: a.id,
        name: a.name,
        url: url,
        is_dev_mode: a.is_dev_mode || false
      };
    })
    .filter(a => a.url);
  
  res.json(activeAssets);
});

/**
 * ADMIN API: List Modules
 */
app.get('/api/admin/assets', (req, res) => {
  res.json(getRegistry());
});

/**
 * ADMIN API: Create Asset
 */
app.post('/api/admin/assets', (req, res) => {
  const { id, name, description } = req.body;
  const registry = getRegistry();
  
  if (registry.find(a => a.id === id)) {
    return res.status(400).json({ error: 'Asset already exists' });
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
 * ADMIN API: Update Asset (Dev Mode toggles)
 */
app.put('/api/admin/assets/:id', (req, res) => {
  const { id } = req.params;
  const registry = getRegistry();
  const index = registry.findIndex(a => a.id === id);
  
  if (index === -1) return res.status(404).json({ error: 'Not found' });

  registry[index] = { ...registry[index], ...req.body };
  saveRegistry(registry);
  res.json(registry[index]);
});

/**
 * ADMIN API: Delete Asset
 */
app.delete('/api/admin/assets/:id', (req, res) => {
  const { id } = req.params;
  const registry = getRegistry();
  const filteredRegistry = registry.filter(a => a.id !== id);
  
  if (registry.length === filteredRegistry.length) {
    return res.status(404).json({ error: 'Asset not found' });
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
 * ADMIN API: Upload Bundle Version
 */
app.post('/api/admin/assets/:id/versions', upload.single('bundle'), (req, res) => {
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
