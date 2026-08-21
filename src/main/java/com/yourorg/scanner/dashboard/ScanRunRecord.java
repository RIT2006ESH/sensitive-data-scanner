package com.yourorg.scanner.dashboard;

import com.yourorg.scanner.model.RiskLevel;
import com.yourorg.scanner.model.ScanResult;

import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;


public class ScanRunRecord {

    private final String runId;
    private final LocalDateTime startTime;
    private final String scanPath;
    private final List<ScanResult> findings = Collections.synchronizedList(new ArrayList<>());
    private final AtomicInteger filesScanned = new AtomicInteger(0);
    private final AtomicInteger filesSkipped = new AtomicInteger(0);
    private final AtomicInteger errorsEncountered = new AtomicInteger(0);

    private volatile ScanRunStatus status = ScanRunStatus.RUNNING;
    private volatile LocalDateTime endTime;
    private volatile Path reportPath;
    private volatile String currentFile;

    private final boolean restored;
    private final long restoredCritical;
    private final long restoredMedium;
    private final long restoredNormal;

    public ScanRunRecord(String runId, LocalDateTime startTime, String scanPath) {
        this(runId, startTime, scanPath, false, 0, 0, 0);
    }

    private ScanRunRecord(String runId, LocalDateTime startTime, String scanPath, boolean restored,
                          long restoredCritical, long restoredMedium, long restoredNormal) {
        this.runId = runId;
        this.startTime = startTime;
        this.scanPath = scanPath;
        this.restored = restored;
        this.restoredCritical = restoredCritical;
        this.restoredMedium = restoredMedium;
        this.restoredNormal = restoredNormal;
    }

    public static ScanRunRecord restored(String runId, ScanRunStatus status, LocalDateTime startTime,
                                         LocalDateTime endTime, String scanPath, int filesScanned, int filesSkipped,
                                         int errorsEncountered, long critical, long medium, long normal,
                                         Path reportPath) {
        ScanRunRecord record = new ScanRunRecord(runId, startTime, scanPath, true, critical, medium, normal);
        record.filesScanned.set(filesScanned);
        record.filesSkipped.set(filesSkipped);
        record.errorsEncountered.set(errorsEncountered);
        record.status = status;
        record.endTime = endTime;
        record.reportPath = reportPath;
        return record;
    }

    public void addFinding(ScanResult result) {
        findings.add(result);
    }

    public void setCurrentFile(String currentFile) { this.currentFile = currentFile; }
    public void incrementFilesScanned() { filesScanned.incrementAndGet(); }
    public void incrementFilesSkipped() { filesSkipped.incrementAndGet(); }
    public void incrementErrorsEncountered() { errorsEncountered.incrementAndGet(); }

    /**
     * Bulk-sets counts in one call rather than incrementing one at a time.
     * Used for runs completed elsewhere (e.g. a local scan agent) that report
     * back a finished total rather than being tracked file-by-file here.
     */
    public void setCounts(int filesScanned, int filesSkipped, int errorsEncountered) {
        this.filesScanned.set(filesScanned);
        this.filesSkipped.set(filesSkipped);
        this.errorsEncountered.set(errorsEncountered);
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
        if (restored) {
            return switch (level) {
                case CRITICAL -> restoredCritical;
                case MEDIUM -> restoredMedium;
                case NORMAL -> restoredNormal;
            };
        }
        synchronized (findings) {
            return findings.stream().filter(f -> f.getRiskLevel() == level).count();
        }
    }
    public List<ScanResult> getRecentFindings(int limit) {
        synchronized (findings) {
            int size = findings.size();
            int from = Math.max(0, size - limit);
            return new ArrayList<>(findings.subList(from, size));
        }
    }

    public boolean isRestored() { return restored; }
    public String getRunId() { return runId; }
    public String getScanPath() { return scanPath; }
    public ScanRunStatus getStatus() { return status; }
    public LocalDateTime getStartTime() { return startTime; }
    public LocalDateTime getEndTime() { return endTime; }
    public List<ScanResult> getFindings() { return findings; }
    public int getFilesScanned() { return filesScanned.get(); }
    public int getFilesSkipped() { return filesSkipped.get(); }
    public int getErrorsEncountered() { return errorsEncountered.get(); }
    public Path getReportPath() { return reportPath; }
    public String getCurrentFile() { return currentFile; }
}