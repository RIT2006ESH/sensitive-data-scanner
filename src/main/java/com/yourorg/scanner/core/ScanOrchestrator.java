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
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.UUID;


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

    /**
     * Runs a scan scoped to exactly the given target paths — typically a
     * single uploaded file's temp path, or a temp folder holding an
     * uploaded batch. This is the only entry point; callers (e.g. the
     * upload controller) must supply what to scan.
     */
    public ScanSummary runScan(List<String> targetPaths) {
        String runId = UUID.randomUUID().toString();
        LocalDateTime startTime = LocalDateTime.now();
        String scanPath = String.join(", ", targetPaths);
        ScanRunRecord record = resultsHolder.startRun(runId, startTime, scanPath);

        log.info("Starting scan run {} for targets: {}", runId, targetPaths);

        try {
            fileWalker.walk(targetPaths, file -> {
                record.setCurrentFile(file.toAbsolutePath().toString());
                processFile(file, record);
            });

            Path reportPath = writeReport(record);

            LocalDateTime endTime = LocalDateTime.now();
            resultsHolder.completeRun(runId, endTime, reportPath);

            log.info("Scan run {} complete. Scanned: {}, Skipped: {}, Errors: {}, Findings: {}",
                    runId, record.getFilesScanned(), record.getFilesSkipped(),
                    record.getErrorsEncountered(), record.getFindings().size());

            return new ScanSummary(startTime, endTime, record.getFilesScanned(),
                    record.getFilesSkipped(), record.getErrorsEncountered(), record.getFindings());

        } catch (RuntimeException e) {
            log.error("Scan run {} failed: {}", runId, e.getMessage(), e);
            resultsHolder.failRun(runId, LocalDateTime.now());
            throw e;
        }
    }

    private void processFile(Path file, ScanRunRecord record) {
        String extension = getExtension(file);

        if (!appProperties.getSupportedExtensions().contains(extension.toLowerCase())) {
            record.incrementFilesSkipped();
            return;
        }

        TextExtractor extractor = extractorFactory.getExtractor(extension);
        if (extractor == null) {
            record.incrementFilesSkipped();
            return;
        }

        try {
            String extractedText = extractor.extractText(file);
            LocalDateTime creationTime = null;
            LocalDateTime modifiedTime = null;
            try {
                BasicFileAttributes attrs = Files.readAttributes(file, BasicFileAttributes.class);
                creationTime = LocalDateTime.ofInstant(attrs.creationTime().toInstant(), ZoneId.systemDefault());
                modifiedTime = LocalDateTime.ofInstant(attrs.lastModifiedTime().toInstant(), ZoneId.systemDefault());
            } catch (IOException e) {
                log.debug("Could not read file attributes for {}: {}", file, e.getMessage());
            }
            detectAndRecordFindings(extractedText, file, record, creationTime, modifiedTime);
            record.incrementFilesScanned();
        } catch (IOException e) {
            log.warn("Failed to extract text from {}: {}", file, e.getMessage());
            record.incrementErrorsEncountered();
        }
    }

    private void detectAndRecordFindings(String extractedText, Path file, ScanRunRecord record,
                                         LocalDateTime creationTime, LocalDateTime modifiedTime) {
        for (SensitiveDataDetector detector : detectorRegistry.getDetectors()) {
            List<String> candidates = detector.detectCandidates(extractedText);

            for (String candidate : candidates) {
                if (isValid(candidate, detector.getType())) {
                    recordFinding(candidate, detector.getType(), file, record, creationTime, modifiedTime);
                }
            }
        }
    }

    private boolean isValid(String candidate, SensitiveDataType type) {
        return switch (type) {
            case CARD_NUMBER -> luhnValidator.isValid(candidate);
            case AADHAAR_NUMBER -> aadhaarValidator.isValid(candidate);
            // Remaining types rely on the detector's own regex/format check as validation.
            case PAN_NUMBER, PASSPORT, DRIVING_LICENCE, VOTER_ID, BANK_ACCOUNT,
                 IFSC, UPI_ID, PHONE_NUMBER, EMAIL -> true;
        };
    }

    private void recordFinding(String candidate, SensitiveDataType type, Path file, ScanRunRecord record,
                               LocalDateTime creationTime, LocalDateTime modifiedTime) {
        String maskedValue = dataMasker.mask(candidate, type);
        RiskLevel riskLevel = riskClassifier.classify(type);

        ScanResult result = new ScanResult(
                file.getFileName().toString(),
                file.toAbsolutePath().toString(),
                type,
                riskLevel,
                maskedValue,
                LocalDateTime.now(),
                creationTime,
                modifiedTime
        );

        record.addFinding(result);
    }

    private Path writeReport(ScanRunRecord record) {
        String format = appProperties.getReport().getFormat();
        ReportGenerator generator = reportWriterFactory.getGenerator(format);

        if (generator == null) {
            log.error("No report generator found for format '{}'. Report not written.", format);
            return null;
        }

        try {
            Path outputDirectory = Paths.get(appProperties.getReport().getOutputDirectory());
            Path reportPath = generator.generateReport(record.getFindings(), outputDirectory);
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
}