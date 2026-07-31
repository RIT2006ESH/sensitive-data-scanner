package com.yourorg.scanner.dashboard;

import com.yourorg.scanner.core.ScanOrchestrator;
import com.yourorg.scanner.model.ScanResult;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * REST API backing the single-page dashboard (static/index.html).
 * Exposes current scan status, live findings, run history, on-demand
 * trigger, and report download.
 */
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
        return run.map(r -> ResponseEntity.ok(r.getFindings()))
                .orElse(ResponseEntity.ok(List.of()));
    }

    @GetMapping("/history")
    public List<ScanRunSummaryDto> getHistory() {
        return resultsHolder.getAllRuns().stream()
                .map(ScanRunSummaryDto::from)
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
    public ResponseEntity<String> triggerScan() {
        if (resultsHolder.isScanRunning()) {
            return ResponseEntity.status(409).body("A scan is already running.");
        }
        new Thread(scanOrchestrator::runScan, "manual-scan-trigger").start();
        return ResponseEntity.accepted().body("Scan started.");
    }
}