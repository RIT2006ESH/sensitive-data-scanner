package com.yourorg.scanner.core;

import com.yourorg.scanner.model.ScanResult;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;


public class ScanContext {

    private final String runId;
    private final LocalDateTime startTime;
    private final List<ScanResult> findings = Collections.synchronizedList(new ArrayList<>());

    private final AtomicInteger filesScanned = new AtomicInteger(0);
    private final AtomicInteger filesSkipped = new AtomicInteger(0);
    private final AtomicInteger errorsEncountered = new AtomicInteger(0);

    private final AtomicLong totalExtractionNanos = new AtomicLong(0);
    private final AtomicLong totalDetectionNanos = new AtomicLong(0);
    private final AtomicLong totalAttributeReadNanos = new AtomicLong(0);
    private volatile long reportWriteNanos = 0;
    private final Map<String, Long> extensionTimeNanos = new ConcurrentHashMap<>();
    private final Map<String, Integer> extensionFileCount = new ConcurrentHashMap<>();

    public ScanContext(String runId, LocalDateTime startTime) {
        this.runId = runId;
        this.startTime = startTime;
    }

    public void addFinding(ScanResult result) {
        findings.add(result);
    }

    public void incrementFilesScanned() { filesScanned.incrementAndGet(); }
    public void incrementFilesSkipped() { filesSkipped.incrementAndGet(); }
    public void incrementErrorsEncountered() { errorsEncountered.incrementAndGet(); }

    public void recordExtractionTime(String extension, long nanos) {
        totalExtractionNanos.addAndGet(nanos);
        extensionTimeNanos.merge(extension.toLowerCase(), nanos, Long::sum);
        extensionFileCount.merge(extension.toLowerCase(), 1, Integer::sum);
    }

    public void recordDetectionTime(long nanos) {
        totalDetectionNanos.addAndGet(nanos);
    }

    public void recordAttributeReadTime(long nanos) {
        totalAttributeReadNanos.addAndGet(nanos);
    }

    public void setReportWriteNanos(long nanos) {
        reportWriteNanos = nanos;
    }

    public String getRunId() { return runId; }
    public LocalDateTime getStartTime() { return startTime; }

    public List<ScanResult> getFindings() { return findings; }

    public int getFilesScanned() { return filesScanned.get(); }
    public int getFilesSkipped() { return filesSkipped.get(); }
    public int getErrorsEncountered() { return errorsEncountered.get(); }
    public long getTotalExtractionNanos() { return totalExtractionNanos.get(); }
    public long getTotalDetectionNanos() { return totalDetectionNanos.get(); }
    public long getTotalAttributeReadNanos() { return totalAttributeReadNanos.get(); }
    public long getReportWriteNanos() { return reportWriteNanos; }
    public Map<String, Long> getExtensionTimeNanos() { return extensionTimeNanos; }
    public Map<String, Integer> getExtensionFileCount() { return extensionFileCount; }
}