package com.yourorg.scanner.dashboard;

import com.yourorg.scanner.model.RiskLevel;
import com.yourorg.scanner.model.ScanResult;

import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Live/historical view of a single scan run, tracked in memory for the
 * web dashboard. Mutated in place while RUNNING, then frozen once
 * COMPLETED/FAILED.
 */
public class ScanRunRecord {

    private final String runId;
    private final LocalDateTime startTime;
    private final List<ScanResult> findings = new CopyOnWriteArrayList<>();
    private final AtomicInteger filesScanned = new AtomicInteger(0);
    private final AtomicInteger filesSkipped = new AtomicInteger(0);
    private final AtomicInteger errorsEncountered = new AtomicInteger(0);

    private volatile ScanRunStatus status = ScanRunStatus.RUNNING;
    private volatile LocalDateTime endTime;
    private volatile Path reportPath;
    private volatile String currentFile;

    public ScanRunRecord(String runId, LocalDateTime startTime) {
        this.runId = runId;
        this.startTime = startTime;
    }

    public void addFinding(ScanResult result) {
        findings.add(result);
    }

    public void setCurrentFile(String currentFile) {
        this.currentFile = currentFile;
    }

    public void incrementFilesScanned() {
        filesScanned.incrementAndGet();
    }

    public void incrementFilesSkipped() {
        filesSkipped.incrementAndGet();
    }

    public void incrementErrorsEncountered() {
        errorsEncountered.incrementAndGet();
    }

    public void complete(LocalDateTime endTime, Path reportPath) {
        this.endTime = endTime;
        this.reportPath = reportPath;
        this.status = ScanRunStatus.COMPLETED;
        this.currentFile = null;
    }

    public void fail(LocalDateTime endTime) {
        this.endTime = endTime;
        this.status = ScanRunStatus.FAILED;
        this.currentFile = null;
    }

    public long countByRisk(RiskLevel level) {
        return findings.stream().filter(f -> f.getRiskLevel() == level).count();
    }

    public String getRunId() {
        return runId;
    }

    public ScanRunStatus getStatus() {
        return status;
    }

    public LocalDateTime getStartTime() {
        return startTime;
    }

    public LocalDateTime getEndTime() {
        return endTime;
    }

    public List<ScanResult> getFindings() {
        return findings;
    }

    public int getFilesScanned() {
        return filesScanned.get();
    }

    public int getFilesSkipped() {
        return filesSkipped.get();
    }

    public int getErrorsEncountered() {
        return errorsEncountered.get();
    }

    public Path getReportPath() {
        return reportPath;
    }

    public String getCurrentFile() {
        return currentFile;
    }
}
