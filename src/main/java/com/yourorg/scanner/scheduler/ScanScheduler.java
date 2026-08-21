package com.yourorg.scanner.scheduler;

import com.yourorg.scanner.config.AppProperties;
import com.yourorg.scanner.core.ScanOptions;
import com.yourorg.scanner.core.ScanOrchestrator;
import com.yourorg.scanner.model.ScanSummary;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class ScanScheduler {

    private static final Logger log = LoggerFactory.getLogger(ScanScheduler.class);

    private final ScanOrchestrator scanOrchestrator;
    private final AppProperties appProperties;

    public ScanScheduler(ScanOrchestrator scanOrchestrator, AppProperties appProperties) {
        this.scanOrchestrator = scanOrchestrator;
        this.appProperties = appProperties;
    }

    @Scheduled(cron = "#{appProperties.scheduleCron}")
    public void triggerScheduledScan() {
        log.info("Scheduled scan triggered");
        ScanSummary summary = scanOrchestrator.runScan(
                appProperties.getTargetDrives(),
                null,
                null,
                ScanOptions.defaults()
        );
        log.info("Scheduled scan finished with {} findings", summary.getFindings().size());
    }
}