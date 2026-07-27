package com.yourorg.scanner.dashboard;

import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory store of scan run history for the web dashboard.
 * Not persisted -- resets on application restart. Keeps every run
 * for the lifetime of the JVM; fine for a Phase-1 internal tool.
 */
@Component
public class ScanResultsHolder {

    private final Map<String, ScanRunRecord> runsById = new ConcurrentHashMap<>();
    private final List<String> runOrder = Collections.synchronizedList(new ArrayList<>());
    private volatile String currentRunId;

    public ScanRunRecord startRun(String runId, LocalDateTime startTime) {
        ScanRunRecord record = new ScanRunRecord(runId, startTime);
        runsById.put(runId, record);
        runOrder.add(0, runId);
        currentRunId = runId;
        return record;
    }

    public void completeRun(String runId, LocalDateTime endTime, Path reportPath) {
        ScanRunRecord record = runsById.get(runId);
        if (record != null) {
            record.complete(endTime, reportPath);
        }
        if (runId.equals(currentRunId)) {
            currentRunId = null;
        }
    }

    public void failRun(String runId, LocalDateTime endTime) {
        ScanRunRecord record = runsById.get(runId);
        if (record != null) {
            record.fail(endTime);
        }
        if (runId.equals(currentRunId)) {
            currentRunId = null;
        }
    }

    public Optional<ScanRunRecord> getCurrentRun() {
        return currentRunId == null ? Optional.empty() : Optional.ofNullable(runsById.get(currentRunId));
    }

    public Optional<ScanRunRecord> getRun(String runId) {
        return Optional.ofNullable(runsById.get(runId));
    }

    public Optional<ScanRunRecord> getLatestRun() {
        synchronized (runOrder) {
            return runOrder.isEmpty() ? Optional.empty() : Optional.ofNullable(runsById.get(runOrder.get(0)));
        }
    }

    public List<ScanRunRecord> getAllRuns() {
        synchronized (runOrder) {
            List<ScanRunRecord> result = new ArrayList<>(runOrder.size());
            for (String id : runOrder) {
                ScanRunRecord record = runsById.get(id);
                if (record != null) {
                    result.add(record);
                }
            }
            return result;
        }
    }

    public boolean isScanRunning() {
        return currentRunId != null;
    }
}
