"""
OpenClaw Telegram command handlers

These are skill definitions that map Telegram commands to API calls.
Place these in your OpenClaw agent's skills directory.
"""

TELEGRAM_COMMANDS = """
# Security Suite Telegram Commands

## /scope set <json>
Set the testing scope for the security suite.

Example:
```
/scope set {"in_scope": ["example.com", "*.example.com"], "out_of_scope": ["admin.example.com"]}
```

## /run start
Start a new security assessment run with the active scope.

## /run status <run_id>
Check the status of a specific run.

Example:
```
/run status run_20260207_123456_abc123
```

## /tasks list
View all tasks in Kanban board format (pending, in progress, completed).

## /tasks move <task_id> <status>
Move a task to a different status.

Example:
```
/tasks move task_abc123 completed
```

## /findings top
Show the top critical and high severity findings.

## /findings list <severity>
List all findings of a specific severity.

Example:
```
/findings list critical
```

## /report generate <run_id>
Generate the final HTML report for a completed run.

Example:
```
/report generate run_20260207_123456_abc123
```

## /report open <run_id>
Get the file path to open the HTML report.

Example:
```
/report open run_20260207_123456_abc123
```
"""


def generate_skill_files():
    """
    Generate OpenClaw skill files for each command

    Copy these to your OpenClaw agent's skills directory:
    ~/.openclaw/agents/<agent-name>/skills/
    """

    skills = {
        "scope-set.md": """# Scope Set Skill

Call the Security Suite API to set the testing scope.

## Usage
```
/scope set {"in_scope": ["example.com"], "out_of_scope": []}
```

## Implementation
```bash
curl -X POST http://localhost:8000/api/scope \\
  -H "Content-Type: application/json" \\
  -d "$1"
```
""",

        "run-start.md": """# Run Start Skill

Start a new security assessment run.

## Usage
```
/run start
```

## Implementation
```bash
# Get active scope
SCOPE=$(curl -s http://localhost:8000/api/scope/active)

# Start run with scope
curl -X POST http://localhost:8000/api/runs/start \\
  -H "Content-Type: application/json" \\
  -d "{\\"scope\\": $SCOPE, \\"dry_run\\": false}"
```
""",

        "run-status.md": """# Run Status Skill

Check the status of a security assessment run.

## Usage
```
/run status run_20260207_123456_abc123
```

## Implementation
```bash
RUN_ID="$1"
curl -s http://localhost:8000/api/runs/$RUN_ID
```
""",

        "tasks-list.md": """# Tasks List Skill

List all tasks in the current run.

## Usage
```
/tasks list
```

## Implementation
```bash
curl -s http://localhost:8000/api/tasks | jq .
```
""",

        "findings-top.md": """# Findings Top Skill

Show top critical and high severity findings.

## Usage
```
/findings top
```

## Implementation
```bash
echo "=== CRITICAL FINDINGS ==="
curl -s "http://localhost:8000/api/findings?severity=critical" | jq '.[] | {id, title, affected_assets}'

echo ""
echo "=== HIGH SEVERITY FINDINGS ==="
curl -s "http://localhost:8000/api/findings?severity=high" | jq '.[] | {id, title, affected_assets}'
```
""",

        "report-generate.md": """# Report Generate Skill

Generate final HTML report for a run.

## Usage
```
/report generate run_20260207_123456_abc123
```

## Implementation
```bash
RUN_ID="$1"
curl -X POST http://localhost:8000/api/reports/$RUN_ID/generate
```
""",

        "report-open.md": """# Report Open Skill

Get the path to the generated HTML report.

## Usage
```
/report open run_20260207_123456_abc123
```

## Implementation
```bash
RUN_ID="$1"
RESPONSE=$(curl -s -X POST http://localhost:8000/api/reports/$RUN_ID/generate)
REPORT_PATH=$(echo $RESPONSE | jq -r '.report_path')
echo "Report available at: $REPORT_PATH"
echo "Open with: open $REPORT_PATH"
```
"""
    }

    return skills


# OpenClaw Integration Guide
OPENCLAW_INTEGRATION_GUIDE = """
# OpenClaw Telegram Integration Guide

## Setup Steps

### 1. Configure OpenClaw Agent

Create or update your OpenClaw agent configuration:

```bash
# Create agent if it doesn't exist
openclaw agents add security-suite \\
  --workspace ~/Desktop/security-suite/telegram \\
  --non-interactive

# Or use existing agent
```

### 2. Add Skills

Copy skill files to the agent's skills directory:

```bash
# Create skills directory
mkdir -p ~/.openclaw/agents/security-suite/skills

# Copy skills (generated from generate_skill_files())
cp scope-set.md ~/.openclaw/agents/security-suite/skills/
cp run-start.md ~/.openclaw/agents/security-suite/skills/
cp run-status.md ~/.openclaw/agents/security-suite/skills/
cp tasks-list.md ~/.openclaw/agents/security-suite/skills/
cp findings-top.md ~/.openclaw/agents/security-suite/skills/
cp report-generate.md ~/.openclaw/agents/security-suite/skills/
cp report-open.md ~/.openclaw/agents/security-suite/skills/
```

### 3. Configure Telegram Access

Update OpenClaw configuration to enable Telegram:

```json
{
  "telegram": {
    "enabled": true,
    "bot_token": "YOUR_TELEGRAM_BOT_TOKEN"
  },
  "agents": {
    "list": [
      {
        "id": "security-suite",
        "name": "Security Suite Controller",
        "model": "ollama/llama3.1:8b",
        "workspace": "~/Desktop/security-suite/telegram"
      }
    ]
  }
}
```

### 4. Start Services

```bash
# Terminal 1: Start API server
cd ~/Desktop/security-suite
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000

# Terminal 2: Start Ollama
ollama serve

# Terminal 3: Start OpenClaw gateway (includes Telegram)
openclaw gateway start
```

### 5. Test via Telegram

Send message to your Telegram bot:

```
/scope set {"in_scope": ["example.com"], "out_of_scope": []}
/run start
/run status <run_id>
/findings top
/report generate <run_id>
```

## API Endpoint Reference

The OpenClaw skills call these API endpoints:

- POST /api/scope - Set scope
- POST /api/runs/start - Start run
- GET /api/runs/{run_id} - Get run status
- GET /api/tasks - List tasks
- PATCH /api/tasks/{task_id} - Update task
- GET /api/findings - List findings
- POST /api/reports/{run_id}/generate - Generate report

## Safety Notes

- All commands enforce the configured scope
- Tool runner uses allowlist for command execution
- Dry-run mode available for testing
- All actions logged to structured JSONL logs
"""
