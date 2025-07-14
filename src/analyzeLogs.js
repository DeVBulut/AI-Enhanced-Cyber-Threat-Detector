import fs from 'fs';
import csv from 'csv-parser';
import { createReadStream } from 'fs';

const DETECTION_CONFIG = {
    // Request frequency thresholds (requests per minute)
    HIGH_FREQUENCY_THRESHOLD: 100,
    MEDIUM_FREQUENCY_THRESHOLD: 50,
    
    // Time window for analysis (in minutes)
    ANALYSIS_WINDOW: 5,
    
    // Suspicious user agent patterns
    SUSPICIOUS_USER_AGENTS: [
        'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python', 'java',
        'go-http-client', 'okhttp', 'requests', 'urllib', 'scrapy'
    ],
    
    // Suspicious IP patterns (private ranges, known bad IPs)
    SUSPICIOUS_IP_PATTERNS: [
        /^10\./, /^172\.(1[6-9]|2[0-9]|3[0-1])\./, /^192\.168\./,
        /^127\./, /^0\.0\.0\.0/, /^255\.255\.255\.255/
    ],
    
    // Suspicious response codes
    SUSPICIOUS_RESPONSE_CODES: ['429', '503', '502', '504'],
    
    // Suspicious request methods
    SUSPICIOUS_METHODS: ['HEAD', 'OPTIONS', 'TRACE', 'CONNECT'],
    
    // Known DDoS attack labels (for supervised datasets)
    KNOWN_DDOS_LABELS: [
        'DrDoS_DNS', 'DrDoS_LDAP', 'DrDoS_MSSQL', 'DrDoS_NetBIOS', 'DrDoS_NTP',
        'DrDoS_SNMP', 'DrDoS_SSDP', 'DrDoS_UDP', 'DrDoS_WebDDoS', 'Syn', 'TFTP',
        'UDP', 'UDP-lag', 'WebDDoS', 'LDAP', 'MSSQL', 'NetBIOS', 'NTP', 'SNMP', 'SSDP'
    ]
};

export async function parseCSVLogs(filePath) {
    return new Promise((resolve, reject) => {
        const parsedResults = [];
        let rowNumber = 1;
        createReadStream(filePath)
            .pipe(csv())
            .on('data', (data) => {
                // Inline mapping logic with validation
                const normalizedLogEntry = {
                    timestamp: data[' Timestamp']?.trim() || 'N/A',
                    sourceIP: data[' Source IP']?.trim() || 'UNKNOWN',
                    destinationIP: data[' Destination IP']?.trim() || 'UNKNOWN',
                    requestCount: parseInt(data[' Total Fwd Packets']) || 1,
                    duration: parseFloat(data[' Flow Duration']) || 0,
                    bytes: parseFloat(data['Total Length of Fwd Packets']) || 0,
                    label: data[' Label']?.trim() || 'N/A',
                    userAgent: 'N/A',
                    responseCode: 'N/A',
                    method: 'N/A',
                    path: 'N/A'
                };
                // Validate required fields
                if (
                    normalizedLogEntry.timestamp === 'N/A' ||
                    normalizedLogEntry.sourceIP === 'UNKNOWN' ||
                    normalizedLogEntry.destinationIP === 'UNKNOWN'
                ) {
                    console.warn(`Warning: Skipping malformed row ${rowNumber} (missing required fields).`);
                } else {
                    parsedResults.push(normalizedLogEntry);
                }
                rowNumber++;
            })
            .on('end', () => {
                console.log(`Parsed ${parsedResults.length} valid log entries from ${filePath}`);
                resolve(parsedResults);
            })
            .on('error', (error) => {
                console.error(`CSV parsing error: ${error.message}`);
                reject(error);
            });
    });
}

function groupByIPAndTime(parsedLogEntries, windowMinutes = DETECTION_CONFIG.ANALYSIS_WINDOW) {
    const ipTimeWindowGroups = {};
    
    parsedLogEntries.forEach(logEntry => {
        const timestamp = new Date(logEntry.timestamp);
        const timeKey = Math.floor(timestamp.getTime() / (windowMinutes * 60 * 1000));
        const key = `${logEntry.sourceIP}_${timeKey}`;
        
        if (!ipTimeWindowGroups[key]) {
            ipTimeWindowGroups[key] = {
                sourceIP: logEntry.sourceIP,
                timeWindow: timeKey,
                entries: [],
                totalRequests: 0,
                uniquePaths: new Set(),
                uniqueUserAgents: new Set(),
                responseCodes: {},
                methods: {},
                labels: new Set(), // Track unique labels
                hasKnownDDoSAttack: false // Flag for known attacks
            };
        }
        
        ipTimeWindowGroups[key].entries.push(logEntry);
        ipTimeWindowGroups[key].totalRequests += logEntry.requestCount;
        ipTimeWindowGroups[key].uniquePaths.add(logEntry.path);
        ipTimeWindowGroups[key].uniqueUserAgents.add(logEntry.userAgent);
        
        // Track labels
        if (logEntry.label && logEntry.label !== 'N/A') {
            ipTimeWindowGroups[key].labels.add(logEntry.label);
            if (isKnownDDoSAttack(logEntry.label)) {
                ipTimeWindowGroups[key].hasKnownDDoSAttack = true;
            }
        }
        
        // Count response codes (only if not N/A)
        if (logEntry.responseCode && logEntry.responseCode !== 'N/A') {
            ipTimeWindowGroups[key].responseCodes[logEntry.responseCode] = 
                (ipTimeWindowGroups[key].responseCodes[logEntry.responseCode] || 0) + logEntry.requestCount;
        }
        
        // Count methods (only if not N/A)
        if (logEntry.method && logEntry.method !== 'N/A') {
            ipTimeWindowGroups[key].methods[logEntry.method] = 
                (ipTimeWindowGroups[key].methods[logEntry.method] || 0) + logEntry.requestCount;
        }
    });
    
    return ipTimeWindowGroups;
}

function isSuspiciousUserAgent(userAgent) {
    if (!userAgent) return false;
    const lowerUA = userAgent.toLowerCase();
    return DETECTION_CONFIG.SUSPICIOUS_USER_AGENTS.some(pattern => 
        lowerUA.includes(pattern.toLowerCase())
    );
}

function isSuspiciousIP(ip) {
    if (!ip) return false;
    return DETECTION_CONFIG.SUSPICIOUS_IP_PATTERNS.some(pattern => 
        pattern.test(ip)
    );
}

function isKnownDDoSAttack(label) {
    if (!label) return false;
    return DETECTION_CONFIG.KNOWN_DDOS_LABELS.some(knownLabel => 
        label.toLowerCase() === knownLabel.toLowerCase()
    );
}

function getLabelRiskScore(label) {
    if (!label) return 0;
    
    const lowerLabel = label.toLowerCase();
    
    // High risk attacks
    if (lowerLabel.includes('drdos_dns') || lowerLabel.includes('drdos_ldap') || 
        lowerLabel.includes('drdos_mssql') || lowerLabel.includes('drdos_ntp') ||
        lowerLabel.includes('drdos_snmp') || lowerLabel.includes('drdos_ssdp')) {
        return 5; // Very high risk
    }
    
    // Medium risk attacks
    if (lowerLabel.includes('drdos_') || lowerLabel.includes('webddos') || 
        lowerLabel.includes('syn') || lowerLabel.includes('udp-lag')) {
        return 4; // High risk
    }
    
    // Lower risk attacks
    if (lowerLabel.includes('udp') || lowerLabel.includes('tftp') || 
        lowerLabel.includes('ldap') || lowerLabel.includes('mssql') ||
        lowerLabel.includes('netbios') || lowerLabel.includes('ntp') ||
        lowerLabel.includes('snmp') || lowerLabel.includes('ssdp')) {
        return 3; // Medium risk
    }
    
    return 0;
}

function calculateRequestFrequency(totalRequests, windowMinutes) {
    return totalRequests / windowMinutes;
}

export function analyzeLogsForDDoS(parsedLogEntries) {
    console.log(`Analyzing ${parsedLogEntries.length} log entries for DDoS indicators...`);
    const ipTimeWindowGroups = groupByIPAndTime(parsedLogEntries);
    const flaggedEntries = [];
    const analysisStats = {
        totalEntries: parsedLogEntries.length,
        uniqueIPs: new Set(parsedLogEntries.map(logEntry => logEntry.sourceIP)).size,
        suspiciousIPs: 0,
        highFrequencyIPs: 0,
        suspiciousUserAgents: 0,
        knownDDoSAttacks: 0,
        labeledAttacks: 0
    };

    // Data-driven indicator rules
    const indicatorRules = [
        {
            check: (group, requestFrequency) => requestFrequency >= DETECTION_CONFIG.HIGH_FREQUENCY_THRESHOLD,
            message: (group, requestFrequency) => `High request frequency: ${requestFrequency.toFixed(2)} req/min`,
            risk: 3,
            statKey: 'highFrequencyIPs',
        },
        {
            check: (group, requestFrequency) => requestFrequency >= DETECTION_CONFIG.MEDIUM_FREQUENCY_THRESHOLD && requestFrequency < DETECTION_CONFIG.HIGH_FREQUENCY_THRESHOLD,
            message: (group, requestFrequency) => `Medium request frequency: ${requestFrequency.toFixed(2)} req/min`,
            risk: 2,
        },
        {
            check: (group) => Array.from(group.uniqueUserAgents).filter(isSuspiciousUserAgent).length > 0,
            message: (group) => `Suspicious user agents: ${Array.from(group.uniqueUserAgents).filter(isSuspiciousUserAgent).join(', ')}`,
            risk: 2,
            statKey: 'suspiciousUserAgents',
        },
        {
            check: (group) => isSuspiciousIP(group.sourceIP),
            message: (group) => `Suspicious IP pattern: ${group.sourceIP}`,
            risk: 1,
            statKey: 'suspiciousIPs',
        },
        {
            check: (group) => Object.entries(group.responseCodes).filter(([code]) => DETECTION_CONFIG.SUSPICIOUS_RESPONSE_CODES.includes(code)).length > 0,
            message: (group) => {
                const suspiciousCodes = Object.entries(group.responseCodes).filter(([code, count]) => DETECTION_CONFIG.SUSPICIOUS_RESPONSE_CODES.includes(code));
                return `Suspicious response codes: ${suspiciousCodes.map(([code, count]) => `${code}(${count})`).join(', ')}`;
            },
            risk: 1,
        },
        {
            check: (group) => group.uniquePaths.size > 50,
            message: (group) => `High path diversity: ${group.uniquePaths.size} unique paths`,
            risk: 1,
        },
        {
            check: (group) => Object.entries(group.methods).filter(([method]) => DETECTION_CONFIG.SUSPICIOUS_METHODS.includes(method)).length > 0,
            message: (group) => {
                const suspiciousMethods = Object.entries(group.methods).filter(([method]) => DETECTION_CONFIG.SUSPICIOUS_METHODS.includes(method));
                return `Suspicious methods: ${suspiciousMethods.map(([method, count]) => `${method}(${count})`).join(', ')}`;
            },
            risk: 1,
        },
    ];

    Object.values(ipTimeWindowGroups).forEach(ipTimeWindowGroup => {
        const requestFrequency = calculateRequestFrequency(
            ipTimeWindowGroup.totalRequests, 
            DETECTION_CONFIG.ANALYSIS_WINDOW
        );
        const suspiciousIndicators = [];
        let riskScore = 0;
        let groupHasDrDoSDNS = false;
        let groupHasLabeledAttack = false;

        // Apply indicator rules
        for (const rule of indicatorRules) {
            if (rule.check(ipTimeWindowGroup, requestFrequency)) {
                suspiciousIndicators.push(rule.message(ipTimeWindowGroup, requestFrequency));
                riskScore += rule.risk;
                if (rule.statKey) {
                    analysisStats[rule.statKey]++;
                }
            }
        }

        // Check for known DDoS attack labels (supervised detection)
        if (ipTimeWindowGroup.labels.size > 0) {
            ipTimeWindowGroup.labels.forEach(label => {
                if (typeof label === 'string' && label.includes('DrDoS_DNS')) {
                    riskScore += 5;
                    suspiciousIndicators.push('DrDoS_DNS attack detected (+5 risk)');
                    analysisStats.knownDDoSAttacks++;
                    groupHasDrDoSDNS = true;
                }
                if (typeof label === 'string' && label.trim().toUpperCase() !== 'BENIGN') {
                    analysisStats.labeledAttacks++;
                    groupHasLabeledAttack = true;
                }
            });
        }

        // If risk score is high enough, flag as suspicious
        if (riskScore >= 2) {
            const flaggedEntry = {
                sourceIP: ipTimeWindowGroup.sourceIP,
                timestamp: new Date().toISOString(),
                requestCount: ipTimeWindowGroup.totalRequests,
                requestFrequency: requestFrequency,
                riskScore: riskScore,
                suspiciousIndicators: suspiciousIndicators,
                uniquePaths: ipTimeWindowGroup.uniquePaths.size,
                uniqueUserAgents: ipTimeWindowGroup.uniqueUserAgents.size,
                responseCodes: ipTimeWindowGroup.responseCodes,
                methods: ipTimeWindowGroup.methods,
                labels: Array.from(ipTimeWindowGroup.labels),
                hasKnownDDoSAttack: ipTimeWindowGroup.hasKnownDDoSAttack || groupHasDrDoSDNS,
                entries: ipTimeWindowGroup.entries.slice(0, 5)
            };
            flaggedEntries.push(flaggedEntry);
        }
    });
    flaggedEntries.sort((a, b) => b.riskScore - a.riskScore);
    return {
        flaggedEntries,
        analysisStats,
        analysisConfig: DETECTION_CONFIG
    };
}

export function generateSummaryReport(analysisOutput) {
    const { flaggedEntries, analysisStats } = analysisOutput;
    
    let report = `=== DDoS Analysis Summary ===\n\n`;
    report += `Total log entries analyzed: ${analysisStats.totalEntries}\n`;
    report += `Unique source IPs: ${analysisStats.uniqueIPs}\n`;
    report += `Suspicious IPs detected: ${analysisStats.suspiciousIPs}\n`;
    report += `High frequency IPs: ${analysisStats.highFrequencyIPs}\n`;
    report += `Suspicious user agents: ${analysisStats.suspiciousUserAgents}\n`;
    report += `Known DDoS attacks detected: ${analysisStats.knownDDoSAttacks}\n`;
    report += `Labeled attack entries: ${analysisStats.labeledAttacks}\n\n`;
    
    if (flaggedEntries.length === 0) {
        report += `✅ No suspicious activity detected.\n`;
    } else {
        report += `🚨 ${flaggedEntries.length} suspicious entries detected:\n\n`;
        
        flaggedEntries.forEach((flaggedEntry, index) => {
            report += `${index + 1}. IP: ${flaggedEntry.sourceIP} (Risk Score: ${flaggedEntry.riskScore})\n`;
            report += `   Requests: ${flaggedEntry.requestCount} (${flaggedEntry.requestFrequency.toFixed(2)} req/min)\n`;
            report += `   Indicators: ${flaggedEntry.suspiciousIndicators.join(', ')}\n\n`;
        });
    }
    
    return report;
} 