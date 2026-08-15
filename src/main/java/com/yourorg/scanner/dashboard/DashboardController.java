package com.yourorg.scanner.dashboard;

import com.yourorg.scanner.core.ScanOrchestrator;
import com.yourorg.scanner.core.ScanOptions;
import com.yourorg.scanner.model.ScanResult;
import com.yourorg.scanner.model.SensitiveDataType;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/scans")
public class DashboardController {

    private final ScanResultsHolder resultsHolder;
    private final ScanOrchestrator scanOrchestrator;

    public DashboardController(ScanResultsHolder resultsHolder, ScanOrchestrator scanOrchestrator) {
        this.resultsHolder = resultsHolder;
        this.scanOrchestrator = scanOrchestrator;
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
        if (resultsHolder.isScanRunning()) {
            return ResponseEntity.status(409).body("A scan is already running.");
        }

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
}