package com.yourorg.scanner.core;

import com.yourorg.scanner.classifier.RiskClassifier;
import com.yourorg.scanner.config.AppProperties;
import com.yourorg.scanner.dashboard.ScanResultsHolder;
import com.yourorg.scanner.dashboard.ScanRunRecord;
import com.yourorg.scanner.detector.DetectorRegistry;
import com.yourorg.scanner.detector.SensitiveDataDetector;
import com.yourorg.scanner.extractor.ExtractorFactory;
import com.yourorg.scanner.extractor.TextExtractor;
import com.yourorg.scanner.mask.DataMasker;
import com.yourorg.scanner.model.RiskLevel;
import com.yourorg.scanner.model.ScanResult;
import com.yourorg.scanner.model.ScanSummary;
import com.yourorg.scanner.model.SensitiveDataType;
import com.yourorg.scanner.report.ReportGenerator;
import com.yourorg.scanner.report.ReportWriterFactory;
import com.yourorg.scanner.validator.AadhaarChecksumValidator;
import com.yourorg.scanner.validator.LuhnValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class ScanOrchestrator {

    private static final Logger log = LoggerFactory.getLogger(ScanOrchestrator.class);

    private final AppProperties appProperties;
    private final FileWalker fileWalker;
    private final ExtractorFactory extractorFactory;
    private final DetectorRegistry detectorRegistry;
    private final LuhnValidator luhnValidator;
    private final AadhaarChecksumValidator aadhaarValidator;
    private final DataMasker dataMasker;
    private final ReportWriterFactory reportWriterFactory;
    private final RiskClassifier riskClassifier;
    private final ScanResultsHolder resultsHolder;

    public ScanOrchestrator(AppProperties appProperties,
                            FileWalker fileWalker,
                            ExtractorFactory extractorFactory,
                            DetectorRegistry detectorRegistry,
                            LuhnValidator luhnValidator,
                            AadhaarChecksumValidator aadhaarValidator,
                            DataMasker dataMasker,
                            ReportWriterFactory reportWriterFactory,
                            RiskClassifier riskClassifier,
                            ScanResultsHolder resultsHolder) {
        this.appProperties = appProperties;
        this.fileWalker = fileWalker;
        this.extractorFactory = extractorFactory;
        this.detectorRegistry = detectorRegistry;
        this.luhnValidator = luhnValidator;
        this.aadhaarValidator = aadhaarValidator;
        this.dataMasker = dataMasker;
        this.reportWriterFactory = reportWriterFactory;
        this.riskClassifier = riskClassifier;
        this.resultsHolder = resultsHolder;
    }

    public ScanSummary runScan() {
        return runScan(null, null, null, null);
    }

    public ScanSummary runScan(List<String> targetPaths) {
        return runScan(targetPaths, null, null, null);
    }

    public ScanSummary runScan(List<String> targetPaths, Set<SensitiveDataType> enabledTypes) {
        return runScan(targetPaths, enabledTypes, null, null);
    }

    public ScanSummary runScan(List<String> targetPaths, Set<SensitiveDataType> enabledTypes,
                               Map<SensitiveDataType, Pattern> customPatterns) {
        return runScan(targetPaths, enabledTypes, customPatterns, null);
    }

    public ScanSummary runScan(List<String> targetPaths, Set<SensitiveDataType> enabledTypes,
                               Map<SensitiveDataType, Pattern> customPatterns, ScanOptions scanOptions) {
        ScanOptions options = scanOptions != null ? scanOptions : ScanOptions.defaults();

        String runId = UUID.randomUUID().toString();
        LocalDateTime startTime = LocalDateTime.now();
        long scanStartNanos = System.nanoTime();
        ScanContext context = new ScanContext(runId, startTime);

        String scanPathDisplay = (targetPaths == null || targetPaths.isEmpty())
                ? String.join(", ", appProperties.getTargetDrives())
                : String.join(", ", targetPaths);
        ScanRunRecord runRecord = resultsHolder.startRun(runId, startTime, scanPathDisplay);

        int permits = appProperties.getConcurrency() > 0
                ? appProperties.getConcurrency()
                : Runtime.getRuntime().availableProcessors() * 4;

        log.info("Starting scan run {}{}{}{} (concurrency: {})", runId,
                (targetPaths == null || targetPaths.isEmpty()) ? "" : " (custom paths: " + targetPaths + ")",
                (enabledTypes == null || enabledTypes.isEmpty()) ? "" : " (types: " + enabledTypes + ")",
                (customPatterns == null || customPatterns.isEmpty()) ? "" : " (custom regex overrides: " + customPatterns.keySet() + ")",
                permits);

        ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
        Semaphore inFlight = new Semaphore(permits);

        try {
            fileWalker.walk(buildWalkTargets(targetPaths), options, file -> {
                try {
                    inFlight.acquire();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                executor.submit(() -> {
                    try {
                        runRecord.setCurrentFile(file.toString());
                        processFile(file, context, runRecord, enabledTypes, customPatterns, options);
                    } finally {
                        inFlight.release();
                    }
                });
            });

            executor.shutdown();
            boolean finished = executor.awaitTermination(24, TimeUnit.HOURS);
            if (!finished) {
                log.warn("Scan run {} did not finish within the 24h safety timeout; forcing shutdown.", runId);
                executor.shutdownNow();
            }

            log.info("Discovery and processing complete for run {}: {} files scanned, {} skipped",
                    runId, context.getFilesScanned(), context.getFilesSkipped());

            long reportWriteStartNanos = System.nanoTime();
            Path reportPath = writeReport(context);
            context.setReportWriteNanos(System.nanoTime() - reportWriteStartNanos);

            LocalDateTime endTime = LocalDateTime.now();
            resultsHolder.completeRun(runId, endTime, reportPath);

            long totalScanNanos = System.nanoTime() - scanStartNanos;

            log.info("Scan run {} complete. Scanned: {}, Skipped: {}, Errors: {}, Findings: {}",
                    runId, context.getFilesScanned(), context.getFilesSkipped(),
                    context.getErrorsEncountered(), context.getFindings().size());

            logPerformanceBreakdown(runId, context, totalScanNanos, permits);

            return new ScanSummary(context.getStartTime(), endTime, context.getFilesScanned(),
                    context.getFilesSkipped(), context.getErrorsEncountered(), context.getFindings());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Scan run {} interrupted", runId);
            resultsHolder.failRun(runId, LocalDateTime.now());
            throw new RuntimeException("Scan interrupted", e);
        } catch (RuntimeException e) {
            log.error("Scan run {} failed: {}", runId, e.getMessage(), e);
            resultsHolder.failRun(runId, LocalDateTime.now());
            throw e;
        } finally {
            if (!executor.isShutdown()) {
                executor.shutdownNow();
            }
        }
    }

    private List<String> buildWalkTargets(List<String> targetPaths) {
        return (targetPaths == null || targetPaths.isEmpty()) ? appProperties.getTargetDrives() : targetPaths;
    }

    private void processFile(Path file, ScanContext context, ScanRunRecord runRecord,
                             Set<SensitiveDataType> enabledTypes, Map<SensitiveDataType, Pattern> customPatterns,
                             ScanOptions options) {
        String extension = getExtension(file);

        List<String> allowedExtensions = (options.fileTypeFilters() != null && !options.fileTypeFilters().isEmpty())
                ? options.fileTypeFilters()
                : appProperties.getSupportedExtensions();

        if (!allowedExtensions.contains(extension.toLowerCase())) {
            context.incrementFilesSkipped();
            runRecord.incrementFilesSkipped();
            return;
        }

        TextExtractor extractor = extractorFactory.getExtractor(extension);
        if (extractor == null) {
            context.incrementFilesSkipped();
            runRecord.incrementFilesSkipped();
            return;
        }

        try {
            long extractStart = System.nanoTime();
            String extractedText = extractor.extractText(file);
            context.recordExtractionTime(extension, System.nanoTime() - extractStart);

            long detectStart = System.nanoTime();
            detectAndRecordFindings(extractedText, file, context, runRecord, enabledTypes, customPatterns);
            context.recordDetectionTime(System.nanoTime() - detectStart);

            context.incrementFilesScanned();
            runRecord.incrementFilesScanned();
        } catch (IOException e) {
            log.warn("Failed to extract text from {}: {}", file, e.getMessage());
            context.incrementErrorsEncountered();
            runRecord.incrementErrorsEncountered();
        } catch (RuntimeException e) {
            log.warn("Unexpected error extracting {}: {}", file, e.getMessage());
            context.incrementErrorsEncountered();
            runRecord.incrementErrorsEncountered();
        }
    }

    private void detectAndRecordFindings(String extractedText, Path file, ScanContext context,
                                         ScanRunRecord runRecord, Set<SensitiveDataType> enabledTypes,
                                         Map<SensitiveDataType, Pattern> customPatterns) {
        for (SensitiveDataDetector detector : detectorRegistry.getDetectors()) {
            SensitiveDataType type = detector.getType();

            if (enabledTypes != null && !enabledTypes.isEmpty() && !enabledTypes.contains(type)) {
                continue;
            }

            List<String> candidates;
            Pattern customPattern = (customPatterns != null) ? customPatterns.get(type) : null;
            if (customPattern != null) {
                candidates = new ArrayList<>();
                Matcher m = customPattern.matcher(extractedText);
                while (m.find()) {
                    candidates.add(m.group());
                }
            } else {
                candidates = detector.detectCandidates(extractedText);
            }

            for (String candidate : candidates) {
                if (isValid(candidate, type)) {
                    recordFinding(candidate, type, file, context, runRecord);
                }
            }
        }
    }

    private boolean isValid(String candidate, SensitiveDataType type) {
        return switch (type) {
            case CARD_NUMBER -> luhnValidator.isValid(candidate);
            case AADHAAR_NUMBER -> aadhaarValidator.isValid(candidate);
            default -> true; // no public checksum for these types; structural regex match only
        };
    }

    private void recordFinding(String candidate, SensitiveDataType type, Path file, ScanContext context, ScanRunRecord runRecord) {
        String maskedValue = dataMasker.mask(candidate, type);
        RiskLevel riskLevel = riskClassifier.classify(type);

        LocalDateTime fileCreationTime = null;
        LocalDateTime fileModifiedTime = null;
        long attrStart = System.nanoTime();
        try {
            BasicFileAttributes attrs = Files.readAttributes(file, BasicFileAttributes.class);
            fileCreationTime = toLocalDateTime(attrs.creationTime().toInstant());
            fileModifiedTime = toLocalDateTime(attrs.lastModifiedTime().toInstant());
        } catch (IOException e) {
            log.debug("Could not read file attributes for {}: {}", file, e.getMessage());
        } finally {
            context.recordAttributeReadTime(System.nanoTime() - attrStart);
        }

        ScanResult result = new ScanResult(
                file.getFileName().toString(),
                file.toAbsolutePath().toString(),
                type,
                riskLevel,
                maskedValue,
                LocalDateTime.now(),
                fileCreationTime,
                fileModifiedTime
        );

        context.addFinding(result);
        runRecord.addFinding(result);
    }

    private LocalDateTime toLocalDateTime(Instant instant) {
        return LocalDateTime.ofInstant(instant, ZoneId.systemDefault());
    }

    private Path writeReport(ScanContext context) {
        String format = appProperties.getReport().getFormat();
        ReportGenerator generator = reportWriterFactory.getGenerator(format);
        if (generator == null) {
            log.error("No report generator found for format '{}'. Report not written.", format);
            return null;
        }
        try {
            Path outputDirectory = Paths.get(appProperties.getReport().getOutputDirectory());
            Path reportPath = generator.generateReport(context.getFindings(), outputDirectory);
            log.info("Report written to {}", reportPath.toAbsolutePath());
            return reportPath;
        } catch (IOException e) {
            log.error("Failed to write scan report: {}", e.getMessage());
            return null;
        }
    }

    private String getExtension(Path file) {
        String name = file.getFileName().toString();
        int lastDot = name.lastIndexOf('.');
        return (lastDot == -1) ? "" : name.substring(lastDot + 1);
    }

    private void logPerformanceBreakdown(String runId, ScanContext context, long totalScanNanos, int concurrency) {
        double totalMs = toMillis(totalScanNanos);
        double extractionMs = toMillis(context.getTotalExtractionNanos());
        double detectionMs = toMillis(context.getTotalDetectionNanos());
        double attrMs = toMillis(context.getTotalAttributeReadNanos());
        double reportMs = toMillis(context.getReportWriteNanos());
        double accountedMs = extractionMs + detectionMs + attrMs + reportMs;
        double effectiveParallelism = totalMs > 0 ? accountedMs / totalMs : 0;

        StringBuilder sb = new StringBuilder();
        sb.append("\n===== Performance breakdown for run ").append(runId).append(" =====\n");
        sb.append(String.format("  Concurrency limit:      %d workers%n", concurrency));
        sb.append(String.format("  Wall-clock duration:    %s%n", formatDuration(totalMs)));
        sb.append(String.format("  Effective parallelism:  %.1fx%n", effectiveParallelism));
        sb.append(String.format("  Text extraction (aggregate): %s%n", formatDuration(extractionMs)));
        sb.append(String.format("  Pattern detection (aggregate): %s%n", formatDuration(detectionMs)));
        sb.append(String.format("  File attribute reads (aggregate): %s%n", formatDuration(attrMs)));
        sb.append(String.format("  Report writing: %s%n", formatDuration(reportMs)));
        sb.append("=====================================================");
        log.info(sb.toString());
    }

    private double toMillis(long nanos) { return nanos / 1_000_000.0; }

    private String formatDuration(double millis) {
        if (millis < 1000) return String.format("%.0f ms", millis);
        Duration d = Duration.ofMillis((long) millis);
        long h = d.toHours(), m = d.toMinutesPart(), s = d.toSecondsPart();
        if (h > 0) return String.format("%dh %dm %ds", h, m, s);
        if (m > 0) return String.format("%dm %ds", m, s);
        return String.format("%.1f s", millis / 1000.0);
    }
}