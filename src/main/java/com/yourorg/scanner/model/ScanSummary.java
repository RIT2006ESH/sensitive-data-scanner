package com.yourorg.scanner.model;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Aggregate statistics for one complete scan run — printed to the log
 * and optionally included at the top of the report.
 */
public class ScanSummary {

    private final LocalDateTime startTime;
    private final LocalDateTime endTime;
    private final int filesScanned;
    private final int filesSkipped;
    private final int errorsEncountered;
    private final List<ScanResult> findings;

    public ScanSummary(LocalDateTime startTime, LocalDateTime endTime, int filesScanned,
                       int filesSkipped, int errorsEncountered, List<ScanResult> findings) {
        this.startTime = startTime;
        this.endTime = endTime;
        this.filesScanned = filesScanned;
        this.filesSkipped = filesSkipped;
        this.errorsEncountered = errorsEncountered;
        this.findings = findings;
    }

    public LocalDateTime getStartTime() {
        return startTime;
    }

    public LocalDateTime getEndTime() {
        return endTime;
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

    public List<ScanResult> getFindings() {
        return findings;
    }
}