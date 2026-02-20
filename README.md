<p align="center">
  <img src="images/AIFT Logo - White Text.png" alt="AIFT Logo" width="400">
</p>

# AIFT — AI Forensic Triage V1.1

**Automated Windows forensic triage, powered by AI.**

AIFT turns hours of manual artifact analysis into minutes. Upload a disk image, select what to parse, and get an AI-generated forensic report — all from your browser, all running locally on your machine.

Built for incident responders who need fast answers, and simple enough for non-forensic team members to operate.

**This project is under active development. Contributions are welcome.**

---

## How It Works

```
Upload Evidence → Select Artifacts → Parse → AI Analysis → HTML Report
```

1. **Run the app** — a local web interface opens in your browser.
2. **Upload evidence** — drag-and-drop an E01, VMDK, VHD, raw image, or archive, or point to a local path for large images.
3. **Pick artifacts** — choose from 25+ Windows forensic artifacts.
4. **Get results** — AI analyzes each artifact for indicators of compromise, correlates findings across artifacts, and generates a self-contained HTML report with evidence hashes and full audit trail.

No Elasticsearch. No Docker. No database. One Python script, one command.

![](images/AIFT.gif)

---

## Example Reports

A [publicly available test image](https://cfreds.nist.gov/all/BenjaminDonnachie/CompromisedWindowsServer2022simulation) (Compromised Windows Server 2022 Simulation by Benjamin Donnachie, NIST CFReDS) was used to compare AI providers. The analysis prompt included one real IOC (`PsExec`) and one not observed IOC (`redpetya.exe`) to test each model's ability to identify true findings and avoid false positives.

| Model | Cost | Runtime | Quality | Report |
|-------|------|---------|---------|--------|
| Kimi | $0.20 | ~5 min | :star::star::star: | [View report](https://flipforensics.github.io/AIFT/example_reports/KIMI.html) |
| OpenAI GPT | $0.94 | ~8 min | :star::star::star::star: | [View report](https://flipforensics.github.io/AIFT/example_reports/ChatGPT5.2.html) |
| Claude Opus 4.6 | $3.01 | ~20 min | :star::star::star::star::star: | [View report](https://flipforensics.github.io/AIFT/example_reports/Opus4.6.html) |

---

## Quick Start

### 1. Install

```bash
git clone https://github.com/<your-repo>/aift.git
cd aift
pip install -r requirements.txt
```

Python 3.10 or higher is required. All dependencies are pure Python — no C libraries, no system packages.

### 2. Run

```bash
python aift.py
```

The app starts and opens your browser to `http://localhost:5000`. On first run, a default `config.yaml` is created automatically.

### 3. Configure your AI provider

Click the **gear icon** (⚙) in the top-right corner of the UI. Select your AI provider and enter the required credentials:

- For **Claude** or **OpenAI**: paste your API key and click Save.
- For **Kimi**: paste your Moonshot API key and click Save.
- For a **local model**: enter your server URL (e.g., `http://localhost:11434/v1`) and model name.

Click **Test Connection** to verify everything works. That's it — you're ready to go.

### 4. Analyze your first image

- Upload evidence by dragging it into the upload area (E01, VMDK, VHD, raw images, ZIP, 7z, tar), or switch to **Path Mode** and enter the file path for large images or directories.
- AIFT opens the image or Triage Package.
- Select artifacts manually or click **Recommended**. You have the option to save your selected artifacts as a profile, and load them in future cases.
- Click **Parse**. Progress is shown in real time.
- Enter your investigation context (e.g., "Suspected unauthorized access between Jan 1-15, 2026. Look for new accounts and remote access tools. IOC identified: abc.exe").
- Click **Analyze**. Per-artifact findings stream in as the AI completes each one, followed by a cross-artifact summary.
- Download the HTML report and/or the raw CSV data.

---

## AI Providers

AIFT supports four AI backends and can be run completely isolated. All configuration is done through the in-app settings page.

| Provider | What You Need | Notes |
|----------|--------------|-------|
| **Anthropic Claude** | API key from [console.anthropic.com](https://console.anthropic.com) | Recommended for analysis quality |
| **OpenAI / GPT** | API key from [platform.openai.com](https://platform.openai.com) | GPT-4o or later |
| **Kimi** | API key from [platform.moonshot.ai](https://platform.moonshot.ai) | Moonshot AI's Kimi K2 — OpenAI-compatible |
| **Local model** | Any OpenAI-compatible server | Ollama, LM Studio, vLLM, text-generation-webui |

### Ollama (local, free, private)

```bash
ollama pull llama3.1:70b
ollama serve
```

In AIFT settings: select **Local**, set URL to `http://localhost:11434/v1`, model to `llama3.1:70b`.

### Kimi

Get an API key from [platform.moonshot.ai](https://platform.moonshot.ai). In AIFT settings: select **Kimi**, paste your key. The default model is `kimi-k2-turbo-preview` (256K context).

### Environment variables

API keys can also be set via environment variables instead of the UI:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
export KIMI_API_KEY="sk-..."
```

---

## Supported Artifacts

AIFT uses [Dissect](https://github.com/fox-it/dissect) by Fox-IT (NCC Group) for forensic parsing — pure Python, no external dependencies.

| Category | Artifacts |
|----------|----------|
| **Persistence** | Run/RunOnce Keys, Scheduled Tasks, Services, WMI Persistence |
| **Execution** | Shimcache, Amcache, Prefetch, BAM/DAM, UserAssist, MUIcache |
| **Event Logs** | Windows Event Logs (all channels), Defender Logs |
| **File System** | NTFS MFT, USN Journal, Recycle Bin |
| **User Activity** | Browser History, Browser Downloads, PowerShell History, Activities Cache |
| **Network** | SRUM Network Data, SRUM Application Usage |
| **Registry** | Shellbags, USB Device History |
| **Security** | SAM User Accounts, Defender Quarantine |

Only artifacts present in the image are shown. Unavailable artifacts are automatically grayed out.

---

## Supported Evidence Formats

AIFT uses [Dissect](https://github.com/fox-it/dissect) for evidence loading, which supports a wide range of forensic image and disk formats.

| Category | Formats | Notes |
|----------|---------|-------|
| **EnCase (EWF)** | `.E01`, `.Ex01`, `.S01`, `.L01` | Split segments (`.E02`, `.E03`, ...) are auto-discovered in the same directory |
| **Raw / DD** | `.dd`, `.img`, `.raw`, `.bin`, `.iso` | Bit-for-bit disk images |
| **Split raw** | `.000`, `.001`, ... | Segmented raw images — pass the first segment |
| **VMware** | `.vmdk`, `.vmx`, `.vmwarevm` | Virtual disk and VM config (auto-loads associated disks) |
| **Hyper-V** | `.vhd`, `.vhdx`, `.vmcx` | Legacy and modern Hyper-V formats |
| **VirtualBox** | `.vdi`, `.vbox` | VirtualBox disk and VM config |
| **QEMU** | `.qcow2`, `.utm` | QEMU Copy-On-Write and UTM bundles |
| **Parallels** | `.hdd`, `.hds`, `.pvm`, `.pvs` | Parallels Desktop images |
| **OVA / OVF** | `.ova`, `.ovf` | Open Virtualization Format |
| **XenServer** | `.xva`, `.vma` | Xen and Proxmox exports |
| **Backup** | `.vbk` | Veeam Backup files |
| **Dissect native** | `.asdf`, `.asif` | Dissect `acquire` output |
| **FTK / AccessData** | `.ad1` | Logical images |
| **Archives** | `.zip`, `.7z`, `.tar`, `.tar.gz` | Extracted and scanned for evidence files inside |

Evidence can also be provided as a **directory path** (e.g., KAPE, Velociraptor, or UAC triage output).

For images over 2 GB, use **Path Mode** instead of uploading — enter the local file path and AIFT reads it directly.

---

## Forensic Integrity

AIFT is built with forensic defensibility in mind:

- **Evidence is read-only.** Disk images are never modified. Dissect opens everything in read-only mode.
- **SHA-256 + MD5 hashing** on intake and before report generation. Hash match is verified and shown in the report.
- **Complete audit trail.** Every action (upload, parse, analyze, report) is logged with UTC timestamps to a per-case `audit.jsonl` file.
- **AI guardrails.** The AI is instructed to cite specific records, state uncertainty explicitly, and never fabricate evidence. Findings include confidence ratings (HIGH / MEDIUM / LOW).
- **Disclaimer in every report.** AI-assisted findings must be verified by a qualified examiner before use in legal or formal proceedings.

---

## Report Output

AIFT generates a **self-contained HTML report** — all CSS inlined, no external dependencies. Open it in any browser, print it, or archive it. The report includes:

- Evidence metadata and hash verification
- Executive summary with confidence assessment
- Per-artifact findings with cited evidence
- Investigation gaps and recommended next steps
- Complete audit trail

Parsed artifact data is also available as a downloadable CSV bundle for further analysis.

---

## Requirements

- Python 3.10+
- 8 GB RAM minimum (for parsing large artifacts)
- Disk space: ~2× the evidence file size (for parsed CSV output)
- No C library dependencies — Dissect is pure Python

---

## Project Structure

```
aift/
├── aift.py              # Entry point — run this
├── config.yaml          # Created on first run
├── requirements.txt     # Python dependencies
├── app/                 # Backend (Flask routes, parsing, analysis, reporting)
├── config/              # Application configuration files
├── images/              # Branding assets
├── profile/             # Artifact selection presets
├── prompts/             # AI prompt templates (customizable)
│   └── artifact_instructions/  # Per-artifact analysis guidance
├── static/              # Frontend assets (CSS + vanilla JS)
├── templates/           # Jinja2 templates (UI + report)
├── tests/               # Unit tests
└── cases/               # Case data (created at runtime)
```

Prompt templates in `prompts/` are plain markdown files. Edit them to tune AI analysis behavior without touching code. 
The `config/artifact_ai_columns.yaml` file controls which columns from each parsed artifact are sent to the AI — edit it to include or exclude fields per artifact to fine-tune what the AI sees.

---

## Disclaimer

AIFT output is AI-assisted. All findings must be independently verified by a qualified forensic examiner before use in any legal, regulatory, or formal investigative proceeding. The AI analyzes only the data provided and may not capture all relevant artifacts or context.

When using a cloud-based AI provider, parsed artifact data is sent to external servers for analysis. Be mindful of the sensitivity of the evidence — if the data is subject to privacy regulations, legal restrictions, or confidentiality requirements, consider using a local model instead.

Contact: info@FlipForensics.com

---

## License

AIFT is released as open source by Flip Forensics and made available at https://github.com/FlipForensics/AIFT. 

License terms: AGPL3 (https://www.gnu.org/licenses/agpl-3.0.html).
