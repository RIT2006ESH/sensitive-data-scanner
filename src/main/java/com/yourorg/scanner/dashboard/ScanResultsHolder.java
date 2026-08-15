package com.yourorg.scanner.dashboard;

import com.yourorg.scanner.config.AppProperties;
import com.yourorg.scanner.model.RiskLevel;
import jakarta.annotation.PostConstruct;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;
import org.apache.commons.csv.CSVRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;


@Component
public class ScanResultsHolder {

    private static final Logger log = LoggerFactory.getLogger(ScanResultsHolder.class);

    private final Map<String, ScanRunRecord> runsById = new ConcurrentHashMap<>();
    private final List<String> runOrder = Collections.synchronizedList(new ArrayList<>());
    private volatile String currentRunId;

    private final AppProperties appProperties;
    private Path manifestPath;

    public ScanResultsHolder(AppProperties appProperties) {
        this.appProperties = appProperties;
    }

    @PostConstruct
    void init() {
        manifestPath = Paths.get(appProperties.getReport().getOutputDirectory(), "scan-history.csv");
        loadManifest();
    }

    public ScanRunRecord startRun(String runId, LocalDateTime startTime, String scanPath) {
        ScanRunRecord record = new ScanRunRecord(runId, startTime, scanPath);
        runsById.put(runId, record);
        runOrder.add(0, runId);
        currentRunId = runId;
        return record;
    }

    public void completeRun(String runId, LocalDateTime endTime, Path reportPath) {
        ScanRunRecord record = runsById.get(runId);
        if (record != null) {
            record.complete(endTime, reportPath);
            appendToManifest(record);
        }
        if (runId.equals(currentRunId)) {
            currentRunId = null;
        }
    }

    public void failRun(String runId, LocalDateTime endTime) {
        ScanRunRecord record = runsById.get(runId);
        if (record != null) {
            record.fail(endTime);
            appendToManifest(record);
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

    private void appendToManifest(ScanRunRecord record) {
        try {
            Files.createDirectories(manifestPath.getParent());

            try (Writer writer = Files.newBufferedWriter(manifestPath,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
                 CSVPrinter printer = new CSVPrinter(writer, CSVFormat.DEFAULT)) {

                printer.printRecord(
                        record.getRunId(),
                        record.getStatus().name(),
                        record.getStartTime(),
                        record.getEndTime(),
                        record.getScanPath() == null ? "" : record.getScanPath(),
                        record.getFilesScanned(),
                        record.getFilesSkipped(),
                        record.getErrorsEncountered(),
                        record.countByRisk(RiskLevel.CRITICAL),
                        record.countByRisk(RiskLevel.MEDIUM),
                        record.countByRisk(RiskLevel.NORMAL),
                        record.getReportPath() == null ? "" : record.getReportPath().toString()
                );
            }
        } catch (IOException e) {
            log.warn("Failed to persist scan run {} to history manifest: {}", record.getRunId(), e.getMessage());
        }
    }

    private void loadManifest() {
        if (!Files.exists(manifestPath)) {
            log.debug("No scan history manifest found at {}, starting with empty history", manifestPath);
            return;
        }

        try (BufferedReader reader = Files.newBufferedReader(manifestPath)) {
            int restoredCount = 0;
            for (CSVRecord csvRecord : CSVFormat.DEFAULT.parse(reader)) {
                if (csvRecord.size() < 12) {
                    continue;
                }
                try {
                    String runId = csvRecord.get(0);
                    ScanRunStatus status = ScanRunStatus.valueOf(csvRecord.get(1));
                    LocalDateTime startTime = LocalDateTime.parse(csvRecord.get(2));
                    LocalDateTime endTime = LocalDateTime.parse(csvRecord.get(3));
                    String scanPath = csvRecord.get(4).isBlank() ? null : csvRecord.get(4);
                    int filesScanned = Integer.parseInt(csvRecord.get(5));
                    int filesSkipped = Integer.parseInt(csvRecord.get(6));
                    int errors = Integer.parseInt(csvRecord.get(7));
                    long critical = Long.parseLong(csvRecord.get(8));
                    long medium = Long.parseLong(csvRecord.get(9));
                    long normal = Long.parseLong(csvRecord.get(10));
                    String reportPathStr = csvRecord.get(11);
                    Path reportPath = reportPathStr.isBlank() ? null : Paths.get(reportPathStr);

                    ScanRunRecord record = ScanRunRecord.restored(runId, status, startTime, endTime, scanPath,
                            filesScanned, filesSkipped, errors, critical, medium, normal, reportPath);

                    runsById.put(runId, record);
                    runOrder.add(0, runId);
                    restoredCount++;
                } catch (Exception e) {
                    log.warn("Skipping unreadable history manifest row: {}", e.getMessage());
                }
            }
            log.info("Restored {} scan run(s) from history manifest", restoredCount);
        } catch (IOException e) {
            log.warn("Failed to read scan history manifest at {}: {}", manifestPath, e.getMessage());
        }
    }
}