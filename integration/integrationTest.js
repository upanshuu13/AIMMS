#!/usr/bin/env node
/**
 * AIMMS Day 9 – Integration Test Suite
 *
 * Simulates real attacks and verifies each module responds correctly.
 * Run AFTER all 5 engines are started (sniffer, rules, profiler, scorer, mitigation).
 *
 * Usage:
 *   node integrationTest.js              (runs all tests)
 *   node integrationTest.js --test brute (runs only brute-force test)
 *   node integrationTest.js --test ports (runs only port-scan test)
 *   node integrationTest.js --test full  (runs combined attack test)
 *
 * ⚠️  Run only on your own VM. Never against external systems.
 */

const { execSync, exec } = require('child_process');
const util   = require('util');
const http   = require('http');
const execA  = util.promisify(exec);

const API_BASE = 'http://localhost:3000/api';
const COLORS   = {
    reset: '\x1b[0m',  green: '\x1b[32m', red:    '\x1b[31m',
    yellow:'\x1b[33m', cyan:  '\x1b[36m', bold:   '\x1b[1m',
    dim:   '\x1b[2m',
};

const pass  = (msg) => console.log(`${COLORS.green}  ✓ ${msg}${COLORS.reset}`);
const fail  = (msg) => console.log(`${COLORS.red}  ✗ ${msg}${COLORS.reset}`);
const info  = (msg) => console.log(`${COLORS.cyan}  → ${msg}${COLORS.reset}`);
const head  = (msg) => console.log(`\n${COLORS.bold}${COLORS.yellow}▶ ${msg}${COLORS.reset}`);
const dim   = (msg) => console.log(`${COLORS.dim}  ${msg}${COLORS.reset}`);

// ─── HTTP helper ──────────────────────────────────────────────────────────────
function apiGet(path) {
    return new Promise((resolve, reject) => {
        http.get(`${API_BASE}${path}`, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try { resolve(JSON.parse(data)); }
                catch { resolve(data); }
            });
        }).on('error', reject);
    });
}

function apiPost(path) {
    return new Promise((resolve, reject) => {
        const req = http.request(`${API_BASE}${path}`, { method: 'POST' }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try { resolve(JSON.parse(data)); }
                catch { resolve(data); }
            });
        });
        req.on('error', reject);
        req.end();
    });
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ─── Check prerequisites ──────────────────────────────────────────────────────
async function checkPrerequisites() {
    head('Checking prerequisites');

    // Check API is reachable
    try {
        await apiGet('/network-events/recent');
        pass('Node.js API is reachable at ' + API_BASE);
    } catch {
        fail('Node.js API is NOT reachable. Start your server first.');
        process.exit(1);
    }

    // Check tools
    for (const tool of ['nmap', 'hydra']) {
        try {
            execSync(`which ${tool}`, { stdio: 'pipe' });
            pass(`${tool} is installed`);
        } catch {
            fail(`${tool} not found. Install with: sudo apt install ${tool}`);
        }
    }
}

// ─── Test 1: Brute-force detection ───────────────────────────────────────────
async function testBruteForce() {
    head('Test 1: SSH Brute-Force Detection');

    info('Launching hydra against localhost (30 seconds)...');
    dim('Command: hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1 -t 4 -w 3');

    // Run hydra in background, kill after 30s
    const hydraProc = exec(
        'hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1 -t 4 -w 3',
        { stdio: 'ignore' }
    );

    await sleep(30_000);
    try { hydraProc.kill(); } catch {}

    info('Triggering rule engine...');
    await apiPost('/incidents/run-rules');
    await sleep(2_000);

    // Verify incident was created
    const incidents = await apiGet('/incidents');
    const bruteForce = Array.isArray(incidents)
        ? incidents.find(i => i.rule_type === 'BRUTE_FORCE')
        : null;

    if (bruteForce) {
        pass(`BRUTE_FORCE incident detected: ${bruteForce.detail}`);
    } else {
        fail('No BRUTE_FORCE incident found. Check your SSH service is running and auth.log is being monitored.');
    }

    // Verify profiler picked it up
    info('Triggering profiler cycle...');
    await apiPost('/profiler/run');
    await sleep(2_000);

    const anomalies = await apiGet('/anomalies');
    const loginAnomaly = Array.isArray(anomalies)
        ? anomalies.find(a => a.anomaly_type === 'LOGIN_SPIKE')
        : null;

    if (loginAnomaly) {
        pass(`LOGIN_SPIKE anomaly: current=${loginAnomaly.current_value} baseline=${loginAnomaly.baseline_value} ratio=${loginAnomaly.deviation_ratio}x`);
    } else {
        info('No LOGIN_SPIKE yet — profiler needs MIN_OBSERVATIONS baseline first. Run this test again after building a baseline.');
    }

    return !!bruteForce;
}

// ─── Test 2: Port scan detection ─────────────────────────────────────────────
async function testPortScan() {
    head('Test 2: Port Scan Detection');

    info('Launching nmap SYN scan against localhost...');
    dim('Command: sudo nmap -sS -p 1-1000 127.0.0.1');

    try {
        execSync('sudo nmap -sS -p 1-1000 127.0.0.1', { stdio: 'pipe', timeout: 60_000 });
        pass('nmap scan completed');
    } catch (err) {
        info('nmap finished (exit code non-zero is normal for SYN scans)');
    }

    await sleep(3_000);

    info('Checking network_events table for scan data...');
    const netEvents = await apiGet('/network-events/recent');
    if (Array.isArray(netEvents) && netEvents.length > 0) {
        pass(`${netEvents.length} network events captured`);
        dim(`Sample: IP=${netEvents[0].source_ip} port=${netEvents[0].port} proto=${netEvents[0].protocol}`);
    } else {
        fail('No network events found. Is sniffer.py running as root?');
        return false;
    }

    info('Triggering rule engine...');
    await apiPost('/incidents/run-rules');
    await sleep(2_000);

    const incidents = await apiGet('/incidents');
    const portScan = Array.isArray(incidents)
        ? incidents.find(i => i.rule_type === 'PORT_SCAN')
        : null;

    if (portScan) {
        pass(`PORT_SCAN incident detected: ${portScan.detail}`);
    } else {
        fail('No PORT_SCAN incident. Check network_events are being populated and threshold is not too high.');
    }

    return !!portScan;
}

// ─── Test 3: Risk scoring ─────────────────────────────────────────────────────
async function testRiskScoring() {
    head('Test 3: Risk Score Accumulation');

    info('Triggering risk scorer...');
    await apiPost('/risk-scores/recalculate');
    await sleep(2_000);

    const scores = await apiGet('/risk-scores');
    if (!Array.isArray(scores) || scores.length === 0) {
        fail('No risk scores found. Run tests 1 and 2 first to generate incidents.');
        return false;
    }

    const top = scores[0];
    pass(`Highest risk IP: ${top.source_ip} | score: ${top.total_score} | level: ${top.risk_level}`);
    dim(`  Breakdown → brute: ${top.score_brute} | portscan: ${top.score_portscan} | anomaly: ${top.score_anomaly} | odd_hour: ${top.score_odd_hour}`);

    const summary = await apiGet('/risk-scores/summary/counts');
    if (Array.isArray(summary)) {
        pass('Risk level summary: ' + summary.map(r => `${r.risk_level}=${r.count}`).join(' | '));
    }

    return top.total_score > 0;
}

// ─── Test 4: Mitigation (dry run) ─────────────────────────────────────────────
async function testMitigation() {
    head('Test 4: Mitigation Engine');

    info('Triggering mitigation scan...');
    await apiPost('/mitigations/run');
    await sleep(2_000);

    const mitigations = await apiGet('/mitigations');
    if (!Array.isArray(mitigations) || mitigations.length === 0) {
        info('No mitigations fired — score may not have hit CRITICAL threshold (90) yet.');
        info('Tip: combine both attacks on the same IP to push score above 90.');
        return false;
    }

    const block = mitigations.find(m => m.action === 'BLOCK');
    if (block) {
        pass(`BLOCK action fired: IP=${block.source_ip} score=${block.trigger_score} level=${block.trigger_level}`);
        pass(`Ban duration: ${block.ban_duration_s ? block.ban_duration_s + 's' : 'permanent'}`);

        // Check active blocks
        const active = await apiGet('/mitigations/active');
        if (Array.isArray(active) && active.length > 0) {
            pass(`${active.length} IP(s) currently blocked`);
        }
    } else {
        const skip = mitigations.find(m => m.action === 'WHITELIST_SKIP');
        if (skip) {
            pass('Whitelist working — 127.0.0.1 was correctly skipped');
            info('To test real blocking, attack from a second VM with a different IP.');
        }
    }

    return true;
}

// ─── Test 5: Full pipeline end-to-end ────────────────────────────────────────
async function testFullPipeline() {
    head('Test 5: Full Pipeline Verification');

    // Check all tables have data
    const checks = [
        { url: '/network-events/recent',  label: 'network_events table' },
        { url: '/incidents',              label: 'incidents table' },
        { url: '/anomalies',              label: 'anomalies table' },
        { url: '/risk-scores',            label: 'risk_scores table' },
        { url: '/mitigations',            label: 'mitigations table' },
        { url: '/profiles',               label: 'user_profiles table' },
    ];

    let allPassed = true;
    for (const check of checks) {
        try {
            const data = await apiGet(check.url);
            const count = Array.isArray(data) ? data.length : 0;
            if (count > 0) {
                pass(`${check.label}: ${count} records`);
            } else {
                fail(`${check.label}: empty — run earlier tests first`);
                allPassed = false;
            }
        } catch (err) {
            fail(`${check.label}: API error — ${err.message}`);
            allPassed = false;
        }
    }

    return allPassed;
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
    const arg = process.argv.find(a => a.startsWith('--test'));
    const filter = arg ? process.argv[process.argv.indexOf(arg) + 1] : 'all';

    console.log(`\n${COLORS.bold}AIMMS Integration Test Suite${COLORS.reset}`);
    console.log(`${'─'.repeat(50)}`);

    await checkPrerequisites();

    const results = {};

    if (filter === 'all' || filter === 'brute') results.brute   = await testBruteForce();
    if (filter === 'all' || filter === 'ports') results.ports   = await testPortScan();
    if (filter === 'all' || filter === 'score') results.score   = await testRiskScoring();
    if (filter === 'all' || filter === 'mitig') results.mitig   = await testMitigation();
    if (filter === 'all' || filter === 'full')  results.full    = await testFullPipeline();

    // Summary
    console.log(`\n${COLORS.bold}${'─'.repeat(50)}`);
    console.log('Test Summary');
    console.log(`${'─'.repeat(50)}${COLORS.reset}`);
    for (const [name, passed] of Object.entries(results)) {
        const icon = passed ? `${COLORS.green}PASS` : `${COLORS.red}FAIL`;
        console.log(`  ${icon}${COLORS.reset}  ${name}`);
    }

    const allPassed = Object.values(results).every(Boolean);
    console.log(`\n${allPassed ? COLORS.green + '✓ All tests passed!' : COLORS.red + '✗ Some tests failed.'} ${COLORS.reset}\n`);
}

main().catch(err => {
    console.error('Fatal:', err.message);
    process.exit(1);
});
