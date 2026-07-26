package com.yourorg.scanner.scheduler;

import com.yourorg.scanner.core.ScanOrchestrator;
import com.yourorg.scanner.model.ScanSummary;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Triggers a full scan on the cron schedule configured in
 * scanner.schedule-cron (application.yml). Delegates all actual work to
 * the ScanOrchestrator — this class's only job is "when", not "how".
 */
@Component
public class ScanScheduler {

    private static final Logger log = LoggerFactory.getLogger(ScanScheduler.class);

    private final ScanOrchestrator scanOrchestrator;

    public ScanScheduler(ScanOrchestrator scanOrchestrator) {
        this.scanOrchestrator = scanOrchestrator;
    }

    @Scheduled(cron = "#{appProperties.scheduleCron}")
    public void triggerScheduledScan() {
        log.info("Scheduled scan triggered");
        ScanSummary summary = scanOrchestrator.runScan();
        log.info("Scheduled scan finished with {} findings", summary.getFindings().size());
    }
}