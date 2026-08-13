package com.yourorg.scanner.dashboard;

import com.yourorg.scanner.core.ScanOrchestrator;
import com.yourorg.scanner.model.ScanResult;
import com.yourorg.scanner.model.SensitiveDataType;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
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
        Optional<ScanRunRecord> run = resultsHolder.getCurrentRun().or(resultsHolder::getLatestRun);
        return run.map(r -> ResponseEntity.ok(ScanRunSummaryDto.from(r)))
                .orElse(ResponseEntity.noContent().build());
    }

    @GetMapping("/current/findings")
    public ResponseEntity<List<ScanResult>> getCurrentFindings() {
        Optional<ScanRunRecord> run = resultsHolder.getCurrentRun().or(resultsHolder::getLatestRun);
        return run.map(r -> ResponseEntity.ok(r.getRecentFindings(200)))
                .orElse(ResponseEntity.ok(List.of()));
    }

    @GetMapping("/history")
    public List<ScanRunSummaryDto> getHistory() {
        return resultsHolder.getAllRuns().stream()
                .map(ScanRunSummaryDto::from)
                .collect(Collectors.toList());
    }

    /** Lets the frontend populate the data-type dropdown without hardcoding values. */
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

    /**
     * Triggers a scan. With no body, scans configured target-drives for all
     * supported data types. "paths" and "dataTypes" in the body each narrow
     * that scope independently -- either, both, or neither may be provided.
     */
    @PostMapping("/trigger")
    public ResponseEntity<String> triggerScan(@RequestBody(required = false) ScanTriggerRequest request) {
        if (resultsHolder.isScanRunning()) {
            return ResponseEntity.status(409).body("A scan is already running.");
        }

        List<String> paths = (request != null) ? request.paths() : null;
        List<String> dataTypeNames = (request != null) ? request.dataTypes() : null;

        if (paths != null && !paths.isEmpty()) {
            List<String> invalid = paths.stream()
                    .filter(p -> !Files.exists(Paths.get(p)))
                    .collect(Collectors.toList());
            if (!invalid.isEmpty()) {
                return ResponseEntity.badRequest()
                        .body("Path(s) do not exist: " + String.join(", ", invalid));
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
                String validOptions = Arrays.stream(SensitiveDataType.values())
                        .map(Enum::name).collect(Collectors.joining(", "));
                return ResponseEntity.badRequest().body(
                        "Invalid data type(s): " + String.join(", ", invalidTypes) +
                                ". Valid options: " + validOptions);
            }
        }

        Set<SensitiveDataType> finalEnabledTypes = enabledTypes;
        new Thread(() -> scanOrchestrator.runScan(paths, finalEnabledTypes), "manual-scan-trigger").start();
        return ResponseEntity.accepted().body("Scan started.");
    }
}