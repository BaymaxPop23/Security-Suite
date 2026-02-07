// Security Suite API Server
const express = require('express');
const cors = require('cors');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date() });
});

// List all agents
app.get('/api/agents', async (req, res) => {
  try {
    const { stdout } = await execPromise('openclaw agents list --json');
    res.json(JSON.parse(stdout));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Execute agent
app.post('/api/agent/:name/execute', async (req, res) => {
  const { name } = req.params;
  const { message } = req.body;

  try {
    const { stdout } = await execPromise(
      `openclaw agent --agent ${name} --message "${message.replace(/"/g, '\\"')}"`
    );
    res.json({ agent: name, response: stdout });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Start scan
app.post('/api/scan/start', async (req, res) => {
  const { target, scope } = req.body;

  // Generate scan ID
  const scanId = `scan_${Date.now()}`;

  // Trigger recon agent
  try {
    const message = `Start reconnaissance on target: ${target}, scope: ${scope}`;
    const { stdout } = await execPromise(
      `openclaw agent --agent recon-agent --message "${message}"`
    );

    res.json({
      scan_id: scanId,
      status: 'started',
      target,
      message: 'Reconnaissance initiated'
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get scan status
app.get('/api/scan/:id/status', (req, res) => {
  const { id } = req.params;
  // TODO: Implement scan status tracking
  res.json({ scan_id: id, status: 'in_progress' });
});

app.listen(PORT, () => {
  console.log(`🚀 Security Suite API running on http://localhost:${PORT}`);
});
