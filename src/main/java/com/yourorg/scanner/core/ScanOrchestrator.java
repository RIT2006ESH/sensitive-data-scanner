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
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
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

    public ScanSummary runScan() {
        String runId = UUID.randomUUID().toString();
        LocalDateTime startTime = LocalDateTime.now();
        ScanContext context = new ScanContext(runId, startTime);
        ScanRunRecord runRecord = resultsHolder.startRun(runId, startTime);

        log.info("Starting scan run {}", runId);

        try {
            fileWalker.walk(file -> {
                runRecord.setCurrentFile(file.toString());
                processFile(file, context, runRecord);
            });

            log.info("Discovery and processing complete for run {}: {} files scanned, {} skipped",
                    runId, context.getFilesScanned(), context.getFilesSkipped());

            Path reportPath = writeReport(context);
            LocalDateTime endTime = LocalDateTime.now();

            // FIX: don't mark a run COMPLETED if no report file was actually
            // produced. Previously completeRun() was called unconditionally,
            // so a run with a failed/null report path would still show up as
            // "completed" in history with a download link that 404s because
            // there's no file on disk to serve.
            if (reportPath == null) {
                log.error("Scan run {} finished processing but no report file was produced; marking run as failed", runId);
                resultsHolder.failRun(runId, endTime);
            } else {
                resultsHolder.completeRun(runId, endTime, reportPath);
            }

            log.info("Scan run {} complete. Scanned: {}, Skipped: {}, Errors: {}, Findings: {}",
                    runId, context.getFilesScanned(), context.getFilesSkipped(),
                    context.getErrorsEncountered(), context.getFindings().size());

            return new ScanSummary(context.getStartTime(), endTime, context.getFilesScanned(),
                    context.getFilesSkipped(), context.getErrorsEncountered(), context.getFindings());
        } catch (RuntimeException e) {
            log.error("Scan run {} failed: {}", runId, e.getMessage(), e);
            resultsHolder.failRun(runId, LocalDateTime.now());
            throw e;
        }
    }

    private void processFile(Path file, ScanContext context, ScanRunRecord runRecord) {
        String extension = getExtension(file);

        if (!appProperties.getSupportedExtensions().contains(extension.toLowerCase())) {
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
            String extractedText = extractor.extractText(file);
            detectAndRecordFindings(extractedText, file, context, runRecord);
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

    private void detectAndRecordFindings(String extractedText, Path file, ScanContext context, ScanRunRecord runRecord) {
        for (SensitiveDataDetector detector : detectorRegistry.getDetectors()) {
            List<String> candidates = detector.detectCandidates(extractedText);

            for (String candidate : candidates) {
                if (isValid(candidate, detector.getType())) {
                    recordFinding(candidate, detector.getType(), file, context, runRecord);
                }
            }
        }
    }

    private boolean isValid(String candidate, SensitiveDataType type) {
        return switch (type) {
            case CARD_NUMBER -> luhnValidator.isValid(candidate);
            case AADHAAR_NUMBER -> aadhaarValidator.isValid(candidate);
            case PAN_NUMBER -> true;
        };
    }

    private void recordFinding(String candidate, SensitiveDataType type, Path file, ScanContext context, ScanRunRecord runRecord) {
        String maskedValue = dataMasker.mask(candidate, type);
        RiskLevel riskLevel = riskClassifier.classify(type);

        ScanResult result = new ScanResult(
                file.getFileName().toString(),
                file.toAbsolutePath().toString(),
                type,
                riskLevel,
                maskedValue,
                LocalDateTime.now()
        );

        context.addFinding(result);
        runRecord.addFinding(result);
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
}