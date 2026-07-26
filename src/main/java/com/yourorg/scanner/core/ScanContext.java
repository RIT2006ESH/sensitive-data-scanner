package com.yourorg.scanner.core;

import com.yourorg.scanner.model.ScanResult;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Mutable state for a single scan run, created fresh by the ScanOrchestrator
 * at the start of every run. Accumulates findings and counters as the walk
 * progresses, then is used to build the final ScanSummary at the end.
 */
public class ScanContext {

    private final String runId;
    private final LocalDateTime startTime;
    private final List<ScanResult> findings = new ArrayList<>();

    private int filesScanned = 0;
    private int filesSkipped = 0;
    private int errorsEncountered = 0;

    public ScanContext(String runId, LocalDateTime startTime) {
        this.runId = runId;
        this.startTime = startTime;
    }

    public void addFinding(ScanResult result) {
        findings.add(result);
    }

    public void incrementFilesScanned() {
        filesScanned++;
    }

    public void incrementFilesSkipped() {
        filesSkipped++;
    }

    public void incrementErrorsEncountered() {
        errorsEncountered++;
    }

    public String getRunId() {
        return runId;
    }

    public LocalDateTime getStartTime() {
        return startTime;
    }

    public List<ScanResult> getFindings() {
        return findings;
    }

    public int getFilesScanned() {
        return filesScanned;
    }

    public int getFilesSkipped() {
        return filesSkipped;
    }

    public int getErrorsEncountered() {
        return errorsEncountered;
    }
}