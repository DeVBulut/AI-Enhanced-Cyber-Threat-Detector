import fetch from 'node-fetch';

export async function queryLLM(promptText) {
    const response = await fetch('http://localhost:11434/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            model: 'mistral',
            prompt: promptText,
            stream: false
        })
    });

    if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
    }

    const result = await response.json();
    return result.response;
}

export function generateDDoSPrompt(flaggedEntry, analysisType = 'explanation') {
    const basePrompt = `You are a cybersecurity expert. Analyze this suspicious log entry in 2-3 sentences maximum:

IP: ${flaggedEntry.sourceIP || 'N/A'}
Requests: ${flaggedEntry.requestCount || 'N/A'}
Time: ${flaggedEntry.timestamp || 'N/A'}
Risk Score: ${flaggedEntry.riskScore || 'N/A'}

`;

    if (analysisType === 'explanation') {
        return basePrompt + `Briefly explain why this might indicate a DDoS attack. Keep response under 100 words.`;
    } else if (analysisType === 'anomaly') {
        return basePrompt + `Suggest 1-2 specific detection rules for this pattern. Keep response under 100 words.`;
    }

    return basePrompt + 'Briefly analyze this entry for DDoS indicators. Keep response under 100 words.';
}

export async function getDDoSExplanation(flaggedEntry) {
    const prompt = generateDDoSPrompt(flaggedEntry, 'explanation');
    return await queryLLM(prompt);
}

export async function getAnomalyDetectionSuggestions(flaggedEntry) {
    const prompt = generateDDoSPrompt(flaggedEntry, 'anomaly');
    return await queryLLM(prompt);
}

export async function getSummaryAnalysis(flaggedEntries) {
    const entriesSummary = flaggedEntries.map((flaggedEntry, index) => 
        `${index + 1}. IP: ${flaggedEntry.sourceIP}, Requests: ${flaggedEntry.requestCount}, Risk: ${flaggedEntry.riskScore}`
    ).join('\n');

    const prompt = `You are a cybersecurity expert. Analyze these suspicious entries in 3-4 sentences maximum:

${entriesSummary}

Provide a brief threat assessment and 1-2 immediate actions. Keep response under 150 words.`;

    return await queryLLM(prompt);
} 