package com.yourorg.scanner.dashboard;

import com.yourorg.scanner.config.AppProperties;
import com.yourorg.scanner.core.ScanOptions;
import com.yourorg.scanner.core.ScanOrchestrator;
import com.yourorg.scanner.model.ScanResult;
import com.yourorg.scanner.model.ScanSummary;
import com.yourorg.scanner.model.SensitiveDataType;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/scans")
public class DashboardController {

    private static final Logger log = LoggerFactory.getLogger(DashboardController.class);
    private static final String AGENT_API_KEY_HEADER = "X-Agent-Api-Key";

    private static final String LUHN_DISCLAIMER =
            "Card number findings passed the Luhn checksum, which only confirms the number is "
                    + "mathematically well-formed. Luhn Pass \u2260 Real/Active Card \u2014 it does NOT "
                    + "confirm the card is genuine, active, or usable.";

    private final ScanResultsHolder resultsHolder;
    private final ScanOrchestrator scanOrchestrator;
    private final AppProperties appProperties;

    public DashboardController(ScanResultsHolder resultsHolder, ScanOrchestrator scanOrchestrator,
                               AppProperties appProperties) {
        this.resultsHolder = resultsHolder;
        this.scanOrchestrator = scanOrchestrator;
        this.appProperties = appProperties;
    }

    @GetMapping("/current")
    public ResponseEntity<ScanRunSummaryDto> getCurrent() {
        Optional<ScanRunRecord> run = resultsHolder.getCurrentRun();
        return run.map(r -> ResponseEntity.ok(ScanRunSummaryDto.from(r)))
                .orElse(ResponseEntity.noContent().build());
    }

    @GetMapping("/current/findings")
    public ResponseEntity<List<ScanResult>> getCurrentFindings() {
        Optional<ScanRunRecord> run = resultsHolder.getCurrentRun();
        return run.map(r -> ResponseEntity.ok(r.getRecentFindings(200)))
                .orElse(ResponseEntity.ok(List.of()));
    }

    @GetMapping("/history")
    public List<ScanRunSummaryDto> getHistory() {
        return resultsHolder.getAllRuns().stream()
                .map(ScanRunSummaryDto::from)
                .collect(Collectors.toList());
    }

    @GetMapping("/data-types")
    public List<String> getAvailableDataTypes() {
        return Arrays.stream(SensitiveDataType.values())
                .map(Enum::name)
                .collect(Collectors.toList());
    }

    @GetMapping("/{runId}/download")
    public ResponseEntity<Resource> downloadReport(@PathVariable String runId) {
        Optional<ScanRunRecord> runOpt = resultsHolder.getRun(runId);
        if (runOpt.isEmpty() || runOpt.get().getReportPath() == null) {
            return ResponseEntity.notFound().build();
        }
        Path reportPath = runOpt.get().getReportPath();
        Resource resource = new FileSystemResource(reportPath);
        if (!resource.exists()) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + reportPath.getFileName() + "\"")
                .body(resource);
    }

    @PostMapping("/trigger")
    public ResponseEntity<String> triggerScan(@RequestBody(required = false) ScanTriggerRequest request) {
        List<String> paths = (request != null) ? request.paths() : null;
        List<String> dataTypeNames = (request != null) ? request.dataTypes() : null;
        Map<String, String> rawCustomPatterns = (request != null) ? request.customPatterns() : null;

        if (paths != null && !paths.isEmpty()) {
            List<String> invalid = paths.stream()
                    .filter(p -> !Files.exists(Paths.get(p)))
                    .collect(Collectors.toList());
            if (!invalid.isEmpty()) {
                return ResponseEntity.badRequest().body("Path(s) do not exist: " + String.join(", ", invalid));
            }
        }

        Set<SensitiveDataType> enabledTypes = null;
        if (dataTypeNames != null && !dataTypeNames.isEmpty()) {
            enabledTypes = EnumSet.noneOf(SensitiveDataType.class);
            List<String> invalidTypes = new ArrayList<>();
            for (String name : dataTypeNames) {
                try {
                    enabledTypes.add(SensitiveDataType.valueOf(name));
                } catch (IllegalArgumentException e) {
                    invalidTypes.add(name);
                }
            }
            if (!invalidTypes.isEmpty()) {
                String validOptions = Arrays.stream(SensitiveDataType.values()).map(Enum::name).collect(Collectors.joining(", "));
                return ResponseEntity.badRequest().body(
                        "Invalid data type(s): " + String.join(", ", invalidTypes) + ". Valid options: " + validOptions);
            }
        }

        Map<SensitiveDataType, Pattern> compiledCustomPatterns = null;
        if (rawCustomPatterns != null && !rawCustomPatterns.isEmpty()) {
            compiledCustomPatterns = new EnumMap<>(SensitiveDataType.class);
            List<String> errors = new ArrayList<>();
            for (Map.Entry<String, String> entry : rawCustomPatterns.entrySet()) {
                String typeName = entry.getKey();
                String regex = entry.getValue();
                if (regex == null || regex.isBlank()) continue;

                SensitiveDataType type;
                try {
                    type = SensitiveDataType.valueOf(typeName);
                } catch (IllegalArgumentException e) {
                    errors.add("Unknown PII type '" + typeName + "' in customPatterns");
                    continue;
                }
                try {
                    compiledCustomPatterns.put(type, Pattern.compile(regex));
                } catch (PatternSyntaxException e) {
                    errors.add("Invalid regex for " + typeName + ": " + e.getMessage());
                }
            }
            if (!errors.isEmpty()) {
                return ResponseEntity.badRequest().body(String.join(" | ", errors));
            }
        }

        List<String> fileTypeFilters = null;
        if (request != null && request.fileTypeFilters() != null && !request.fileTypeFilters().isEmpty()) {
            fileTypeFilters = request.fileTypeFilters().stream()
                    .map(ext -> ext.startsWith(".") ? ext.substring(1) : ext)
                    .map(String::toLowerCase)
                    .collect(Collectors.toList());
        }

        ScanOptions scanOptions = new ScanOptions(
                request == null || request.recursive() == null || request.recursive(),
                request == null || request.includeHiddenFiles() == null || request.includeHiddenFiles(),
                request == null || request.excludeConfiguredPaths() == null || request.excludeConfiguredPaths(),
                request != null && request.followSymbolicLinks() != null && request.followSymbolicLinks(),
                fileTypeFilters
        );

        List<String> finalPaths = paths;
        Set<SensitiveDataType> finalEnabledTypes = enabledTypes;
        Map<SensitiveDataType, Pattern> finalCustomPatterns = compiledCustomPatterns;
        new Thread(() -> scanOrchestrator.runScan(finalPaths, finalEnabledTypes, finalCustomPatterns, scanOptions),
                "manual-scan-trigger").start();
        return ResponseEntity.accepted().body("Scan started.");
    }

    /**
     * Accepts a single file uploaded directly from the browser and scans
     * ONLY that file — never the server's own drives. The file is written
     * to a short-lived temp location for the duration of the scan and
     * deleted immediately afterward, whether the scan succeeds or fails.
     */
    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> uploadAndScan(@RequestParam("file") MultipartFile file) {
        if (file == null || file.isEmpty()) {
            return ResponseEntity.badRequest().body("No file provided.");
        }

        String originalName = file.getOriginalFilename();
        if (originalName == null || originalName.isBlank()) {
            return ResponseEntity.badRequest().body("Uploaded file has no name.");
        }
        // Strip any path portion the client might send, so we only ever use
        // the bare filename (prevents writing outside the intended temp dir).
        String safeName = Paths.get(originalName).getFileName().toString();

        Path tempDir;
        Path tempFile;
        try {
            tempDir = Files.createTempDirectory("scan-upload-");
            tempFile = tempDir.resolve(safeName);
            file.transferTo(tempFile);
        } catch (IOException e) {
            log.error("Failed to stage uploaded file for scanning: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Could not save the uploaded file for scanning.");
        }

        try {
            ScanSummary summary = scanOrchestrator.runScan(
                    List.of(tempFile.toString()),
                    null,
                    null,
                    ScanOptions.defaults()
            );

            List<String> notices = new ArrayList<>();
            boolean hasCardFindings = summary.getFindings().stream()
                    .anyMatch(f -> f.getDataType() == SensitiveDataType.CARD_NUMBER);
            if (hasCardFindings) {
                notices.add(LUHN_DISCLAIMER);
            }

            return ResponseEntity.ok(new UploadScanResponse(summary, notices));

        } finally {
            // Sensitive content shouldn't linger on disk any longer than the scan itself.
            deleteQuietly(tempFile);
            deleteQuietly(tempDir);
        }
    }

    private void deleteQuietly(Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (IOException e) {
            log.warn("Could not delete temp file/dir {}: {}", path, e.getMessage());
        }
    }

    /**
     * Receives a completed scan result from the desktop scan agent, which
     * scans the customer's own local drive and never uploads raw files here —
     * only the finished, already-masked findings and counts. Requires the
     * X-Agent-Api-Key header to match scanner.agent-api-key.
     */
    @PostMapping("/external-report")
    public ResponseEntity<String> submitExternalReport(
            @RequestHeader(value = AGENT_API_KEY_HEADER, required = false) String providedKey,
            @RequestBody ExternalScanReportRequest request) {

        String expectedKey = appProperties.getAgentApiKey();
        if (expectedKey == null || expectedKey.isBlank()) {
            log.error("scanner.agent-api-key is not configured — rejecting all external reports until it is set.");
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body("Agent reporting is not configured on this server.");
        }
        if (providedKey == null || !constantTimeEquals(providedKey, expectedKey)) {
            log.warn("Rejected external scan report: missing or invalid {} header.", AGENT_API_KEY_HEADER);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid or missing agent API key.");
        }

        if (request == null) {
            return ResponseEntity.badRequest().body("Request body is required.");
        }
        if (request.startTime() == null || request.endTime() == null) {
            return ResponseEntity.badRequest().body("startTime and endTime are required.");
        }
        if (request.status() == null || request.status().isBlank()) {
            return ResponseEntity.badRequest().body("status is required (COMPLETED or FAILED).");
        }

        ScanRunStatus status;
        try {
            status = ScanRunStatus.valueOf(request.status().toUpperCase());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(
                    "Invalid status '" + request.status() + "'. Expected COMPLETED or FAILED.");
        }

        ScanRunRecord record = resultsHolder.recordExternalRun(
                request.runId(),
                request.startTime(),
                request.endTime(),
                request.scanPath(),
                request.filesScanned(),
                request.filesSkipped(),
                request.errorsEncountered(),
                request.findings(),
                status
        );

        return ResponseEntity.accepted().body("Recorded run " + record.getRunId());
    }

    private boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8)
        );
    }
}