package com.yourorg.scanner.core;

import com.yourorg.scanner.classifier.RiskClassifier;
import com.yourorg.scanner.config.AppProperties;
import com.yourorg.scanner.detector.DetectorRegistry;
import com.yourorg.scanner.detector.SensitiveDataDetector;
import com.yourorg.scanner.extractor.ExtractorFactory;
import com.yourorg.scanner.extractor.TextExtractor;
import com.yourorg.scanner.mask.DataMasker;
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

/**
 * Coordinates the full scan pipeline end-to-end:
 * walk -> extract -> detect -> validate -> mask -> aggregate -> report.
 * This is the single class that ties every other layer together; nothing
 * here does the actual extraction/detection/validation work itself.
 */
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

    public ScanOrchestrator(AppProperties appProperties,
                            FileWalker fileWalker,
                            ExtractorFactory extractorFactory,
                            DetectorRegistry detectorRegistry,
                            LuhnValidator luhnValidator,
                            AadhaarChecksumValidator aadhaarValidator,
                            DataMasker dataMasker,
                            ReportWriterFactory reportWriterFactory) {
        this.appProperties = appProperties;
        this.fileWalker = fileWalker;
        this.extractorFactory = extractorFactory;
        this.detectorRegistry = detectorRegistry;
        this.luhnValidator = luhnValidator;
        this.aadhaarValidator = aadhaarValidator;
        this.dataMasker = dataMasker;
        this.reportWriterFactory = reportWriterFactory;
    }

    /**
     * Runs one complete scan: discovers files, processes each one, then
     * writes the final report. Any per-file failure is logged and skipped
     * rather than aborting the whole run.
     */
    public ScanSummary runScan() {
        String runId = UUID.randomUUID().toString();
        ScanContext context = new ScanContext(runId, LocalDateTime.now());

        log.info("Starting scan run {}", runId);

        List<Path> discoveredFiles = fileWalker.walk();
        log.info("Discovered {} files to process", discoveredFiles.size());

        for (Path file : discoveredFiles) {
            processFile(file, context);
        }

        writeReport(context);

        LocalDateTime endTime = LocalDateTime.now();
        log.info("Scan run {} complete. Scanned: {}, Skipped: {}, Errors: {}, Findings: {}",
                runId, context.getFilesScanned(), context.getFilesSkipped(),
                context.getErrorsEncountered(), context.getFindings().size());

        return new ScanSummary(context.getStartTime(), endTime, context.getFilesScanned(),
                context.getFilesSkipped(), context.getErrorsEncountered(), context.getFindings());
    }

    private void processFile(Path file, ScanContext context) {
        String extension = getExtension(file);

        if (!appProperties.getSupportedExtensions().contains(extension.toLowerCase())) {
            context.incrementFilesSkipped();
            return;
        }

        TextExtractor extractor = extractorFactory.getExtractor(extension);
        if (extractor == null) {
            context.incrementFilesSkipped();
            return;
        }

        try {
            String extractedText = extractor.extractText(file);
            detectAndRecordFindings(extractedText, file, context);
            context.incrementFilesScanned();
        } catch (IOException e) {
            log.warn("Failed to extract text from {}: {}", file, e.getMessage());
            context.incrementErrorsEncountered();
        }
    }

    private void detectAndRecordFindings(String extractedText, Path file, ScanContext context) {
        for (SensitiveDataDetector detector : detectorRegistry.getDetectors()) {
            List<String> candidates = detector.detectCandidates(extractedText);

            for (String candidate : candidates) {
                if (isValid(candidate, detector.getType())) {
                    recordFinding(candidate, detector.getType(), file, context);
                }
            }
        }
    }

    private boolean isValid(String candidate, SensitiveDataType type) {
        return switch (type) {
            case CARD_NUMBER -> luhnValidator.isValid(candidate);
            case AADHAAR_NUMBER -> aadhaarValidator.isValid(candidate);
            case PAN_NUMBER -> true; // regex format check in the detector IS the validation
        };
    }

    private void recordFinding(String candidate, SensitiveDataType type, Path file, ScanContext context) {
        String maskedValue = dataMasker.mask(candidate, type);

        ScanResult result = new ScanResult(
                file.getFileName().toString(),
                file.toAbsolutePath().toString(),
                type,
                maskedValue,
                LocalDateTime.now()
        );

        context.addFinding(result);
    }

    private void writeReport(ScanContext context) {
        String format = appProperties.getReport().getFormat();
        ReportGenerator generator = reportWriterFactory.getGenerator(format);

        if (generator == null) {
            log.error("No report generator found for format '{}'. Report not written.", format);
            return;
        }

        try {
            Path outputDirectory = Paths.get(appProperties.getReport().getOutputDirectory());
            Path reportPath = generator.generateReport(context.getFindings(), outputDirectory);
            log.info("Report written to {}", reportPath.toAbsolutePath());
        } catch (IOException e) {
            log.error("Failed to write scan report: {}", e.getMessage());
        }
    }

    private String getExtension(Path file) {
        String name = file.getFileName().toString();
        int lastDot = name.lastIndexOf('.');
        return (lastDot == -1) ? "" : name.substring(lastDot + 1);
    }
}