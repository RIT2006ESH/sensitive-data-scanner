package com.yourorg.scanner.dashboard;

import com.yourorg.scanner.model.ScanResult;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Payload the desktop scan agent POSTs once it finishes scanning a
 * customer's local drive. The agent has already done all detection,
 * validation, and masking locally — this carries only the finished
 * result (counts + masked findings), never raw file contents.
 *
 * status: "COMPLETED" or "FAILED" (matches ScanRunStatus).
 */
public record ExternalScanReportRequest(
        String runId,
        LocalDateTime startTime,
        LocalDateTime endTime,
        String scanPath,
        int filesScanned,
        int filesSkipped,
        int errorsEncountered,
        List<ScanResult> findings,
        String status
) {
}