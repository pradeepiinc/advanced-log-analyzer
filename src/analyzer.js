// Heuristic log analyzer to extract high-level performance metrics and NFRs

const DEFAULT_THRESHOLDS = {
  p95LatencyMs: 500,
  p99LatencyMs: 1000,
  errorRate: 0.01,
  cpuUtilization: 0.8,
  memoryUtilization: 0.85,
  saturationLoadAvg: 1.0
};

function parseNumbersFromLine(line) {
  const numbers = [];
  const regex = /[-+]?(?:\d*\.\d+|\d+)(?:e[-+]?\d+)?/gi;
  let match;
  while ((match = regex.exec(line)) !== null) {
    numbers.push(Number(match[0]));
  }
  return numbers;
}

function percentile(sortedValues, p) {
  if (!sortedValues.length) return 0;
  const idx = Math.ceil((p / 100) * sortedValues.length) - 1;
  return sortedValues[Math.max(0, Math.min(sortedValues.length - 1, idx))];
}

function analyzeLogsFromText(text) {
  const lines = text.split(/\r?\n/).filter(Boolean);

  const responseTimes = [];
  let requestCount = 0;
  let errorCount = 0;
  let totalBytes = 0;
  const cpuSamples = [];
  const memSamples = [];
  const loadAvgSamples = [];

  for (const line of lines) {
    const l = line.toLowerCase();

    // Detect errors
    if (/(error|exception|fail|timeout|5\d{2})/.test(l)) {
      errorCount += 1;
    }

    // Try to parse response time ms patterns
    // Examples: "response_time=123ms", "took 345 ms", "latency: 1.23s"
    let rtMatch = l.match(/(response_time|latency|duration|took)[^\d]*([\d.]+)\s*(ms|s|sec|seconds|millisecond)/);
    if (rtMatch) {
      const val = parseFloat(rtMatch[2]);
      const unit = rtMatch[3];
      const ms = /s/.test(unit) && unit !== 'ms' ? val * 1000 : val;
      responseTimes.push(ms);
      requestCount += 1;
    } else if (/\s(20\d|30\d|40\d|50\d)\s/.test(l) && /\s(\d+)$/.test(l)) {
      // Common access log: "... \"GET /\" 200 123 45ms" or bytes at end
      const numCandidates = parseNumbersFromLine(l);
      if (numCandidates.length >= 2) {
        const last = numCandidates[numCandidates.length - 1];
        if (last < 120000) { // plausibly a duration in ms
          responseTimes.push(last);
          requestCount += 1;
        }
        const secondLast = numCandidates[numCandidates.length - 2];
        if (secondLast > 0) totalBytes += secondLast;
      }
    }

    // CPU patterns
    const cpuMatch = l.match(/cpu\s*(avg|usage|util(?:ization)?)?[^\d]*([\d.]+)\s*%/);
    if (cpuMatch) cpuSamples.push(Number(cpuMatch[2]) / 100);

    // Memory patterns
    const memMatch = l.match(/mem(?:ory)?\s*(usage|util(?:ization)?)?[^\d]*([\d.]+)\s*%/);
    if (memMatch) memSamples.push(Number(memMatch[2]) / 100);

    // Load average
    const loadMatch = l.match(/load(?:\s*avg(?:erage)?)?[^\d]*([\d.]+)/);
    if (loadMatch) loadAvgSamples.push(Number(loadMatch[1]));
  }

  responseTimes.sort((a, b) => a - b);
  const p50 = percentile(responseTimes, 50);
  const p90 = percentile(responseTimes, 90);
  const p95 = percentile(responseTimes, 95);
  const p99 = percentile(responseTimes, 99);

  const errorRate = requestCount > 0 ? errorCount / requestCount : 0;
  const avgThroughputRps = (() => {
    // Approximate by counting lines with durations and assuming uniform timestamps when not available
    // For an app with timestamps we could bucket by minute; here return requests per second over the log span
    // Fall back to responseTimes length / 60 as rough guess
    const approxSeconds = Math.max(60, Math.ceil(lines.length / 50));
    return responseTimes.length / approxSeconds;
  })();

  const avgCpu = cpuSamples.length ? cpuSamples.reduce((a, b) => a + b, 0) / cpuSamples.length : null;
  const avgMem = memSamples.length ? memSamples.reduce((a, b) => a + b, 0) / memSamples.length : null;
  const avgLoad = loadAvgSamples.length ? loadAvgSamples.reduce((a, b) => a + b, 0) / loadAvgSamples.length : null;

  const thresholds = DEFAULT_THRESHOLDS;

  const recommendations = [];
  if (p95 && p95 > thresholds.p95LatencyMs) {
    recommendations.push(`Improve p95 latency to <= ${thresholds.p95LatencyMs} ms (observed ${Math.round(p95)} ms). Consider caching, DB indexing, or reducing external calls.`);
  }
  if (p99 && p99 > thresholds.p99LatencyMs) {
    recommendations.push(`Reduce long-tail p99 latency to <= ${thresholds.p99LatencyMs} ms; investigate GC pauses, cold paths, and lock contention.`);
  }
  if (errorRate > thresholds.errorRate) {
    recommendations.push(`Reduce error rate to <= ${(thresholds.errorRate * 100).toFixed(2)}% (observed ${(errorRate * 100).toFixed(2)}%). Ensure retries, timeouts, circuit breakers.`);
  }
  if (avgCpu !== null && avgCpu > thresholds.cpuUtilization) {
    recommendations.push(`CPU utilization high (${Math.round(avgCpu * 100)}%). Plan capacity to keep avg CPU <= ${Math.round(thresholds.cpuUtilization * 100)}%.`);
  }
  if (avgMem !== null && avgMem > thresholds.memoryUtilization) {
    recommendations.push(`Memory utilization high (${Math.round(avgMem * 100)}%). Tune heap sizes, fix leaks, or scale memory.`);
  }
  if (avgLoad !== null && avgLoad > thresholds.saturationLoadAvg) {
    recommendations.push(`System load average indicates saturation (${avgLoad.toFixed(2)}). Increase concurrency limits or add capacity.`);
  }

  const nfr = buildNfrFromMetrics({
    p50LatencyMs: p50,
    p90LatencyMs: p90,
    p95LatencyMs: p95,
    p99LatencyMs: p99,
    errorRate,
    avgThroughputRps,
    cpuUtilization: avgCpu,
    memoryUtilization: avgMem,
    saturationLoadAvg: avgLoad
  }, thresholds);

  return {
    metrics: {
      requests: requestCount,
      errors: errorCount,
      errorRate,
      throughputRps: avgThroughputRps,
      totalBytesServed: totalBytes,
      latency: { p50, p90, p95, p99 }
    },
    system: {
      cpuUtilization: avgCpu,
      memoryUtilization: avgMem,
      loadAverage: avgLoad
    },
    nfr,
    recommendations
  };
}

function buildNfrFromMetrics(metrics, thresholds) {
  const nonFunctionalRequirements = [];

  nonFunctionalRequirements.push({
    category: 'Latency',
    requirement: `p95 <= ${thresholds.p95LatencyMs} ms; p99 <= ${thresholds.p99LatencyMs} ms`,
    current: `p95=${Math.round(metrics.p95LatencyMs || 0)} ms; p99=${Math.round(metrics.p99LatencyMs || 0)} ms`
  });
  nonFunctionalRequirements.push({
    category: 'Reliability',
    requirement: `Error rate <= ${(thresholds.errorRate * 100).toFixed(2)}%`,
    current: `Error rate ${(metrics.errorRate * 100).toFixed(2)}%`
  });
  nonFunctionalRequirements.push({
    category: 'Throughput',
    requirement: `Sustain >= ${Math.max(1, Math.round((metrics.avgThroughputRps || 1) * 1.5))} RPS with SLO latency`,
    current: `${metrics.avgThroughputRps?.toFixed(2) || '0.00'} RPS observed`
  });
  if (metrics.cpuUtilization !== null) {
    nonFunctionalRequirements.push({
      category: 'Capacity',
      requirement: `Avg CPU <= ${Math.round(thresholds.cpuUtilization * 100)}%`,
      current: `Avg CPU ${Math.round(metrics.cpuUtilization * 100)}%`
    });
  }
  if (metrics.memoryUtilization !== null) {
    nonFunctionalRequirements.push({
      category: 'Capacity',
      requirement: `Avg Memory <= ${Math.round(thresholds.memoryUtilization * 100)}%`,
      current: `Avg Memory ${Math.round(metrics.memoryUtilization * 100)}%`
    });
  }
  return nonFunctionalRequirements;
}

export { analyzeLogsFromText };


