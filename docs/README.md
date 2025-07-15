# AI Enchanced Network Scanner

A Node.js tool for detecting DDoS attacks in network traffic logs using both heuristics and local LLM analysis (Ollama + Mistral). Supports HTTP and CIC-DDoS2019 flow logs.

## Quick Start

1. **Install dependencies:**
   ```bash
   npm install
   ```
2. **Run analysis:**
   ```bash
   node src/app.js logs.csv
   ```
3. **Generate sample data:**
   ```bash
   node src/app.js --generate-sample sample 200
   ```
4. **Test LLM connection:**
   ```bash
   node src/app.js --test-llm
   ```
## Command-Line Options
- `--help, -h` Show help
- `--test-llm` Test LLM connection
- `--generate-sample <file> <count>` Generate sample CSV data
- `--no-llm` Disable LLM analysis
- `--no-save` Don't save results to file
- `--max-llm <number>` Max entries for LLM analysis (default: 3)
- `--output <file>` Output file (default: ddos-analysis-results.json)

### Example: Run with options
```bash
node src/app.js logs.csv --max-llm 4 --output results.json
```

## CSV Format
```
timestamp,sourceIP,destinationIP,requestCount,userAgent,responseCode,method,path,bytes,duration
2024-01-15T10:30:00Z,192.168.1.100,10.0.0.1,1,"Mozilla/5.0",200,GET,/api/data,1024,0.150
```

For more details, see code comments or the documentation file. 