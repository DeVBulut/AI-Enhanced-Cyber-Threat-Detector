# DDoS Detection System — Documentation

## Overview
This Node.js tool analyzes network logs for DDoS attacks using heuristics and local LLM (Ollama) analysis. It supports both HTTP and CIC-DDoS2019 flow logs.

## Architecture
- **src/app.js** — CLI entry point
- **src/ddosDetectionSystem.js** — Main detection logic (modularized)
- **analyzeLogs.js** — Heuristic/statistical analysis
- **llmAssist.js** — LLM integration (Ollama)

## How It Works (Short Version)
1. **Parse CSV logs** (flexible columns)
2. **Apply detection rules** (frequency, user agent, IP, response code, etc.)
3. **Score and flag suspicious entries**
4. **(Optional) LLM analysis** for explanations and suggestions
5. **Output**: Console summary and JSON file

## Usage Example
```bash
node src/app.js logs.csv --max-llm 5 --output results.json
```

## Configuration
Detection thresholds and other settings are in `analyzeLogs.js` and `src/ddosDetectionSystem.js` (see `CONFIG` and `DETECTION_CONFIG`).

## Tips
- If you get no suspicious entries, lower thresholds in the config or generate more aggressive sample data.
- For LLM errors, ensure Ollama is running and the Mistral model is installed.

For further details, see code comments or the README. 