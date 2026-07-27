package com.yourorg.scanner.dashboard;

import com.yourorg.scanner.model.RiskLevel;

import java.time.LocalDateTime;

public record ScanRunSummaryDto(
        String runId,
        String status,
        LocalDateTime startTime,
        LocalDateTime endTime,
        int filesScanned,
        int filesSkipped,
        int errorsEncountered,
        long criticalCount,
        long mediumCount,
        long normalCount,
        String currentFile
) {
    public static ScanRunSummaryDto from(ScanRunRecord record) {
        return new ScanRunSummaryDto(
                record.getRunId(),
                record.getStatus().name(),
                record.getStartTime(),
                record.getEndTime(),
                record.getFilesScanned(),
                record.getFilesSkipped(),
                record.getErrorsEncountered(),
                record.countByRisk(RiskLevel.CRITICAL),
                record.countByRisk(RiskLevel.MEDIUM),
                record.countByRisk(RiskLevel.NORMAL),
                record.getCurrentFile()
        );
    }
}
