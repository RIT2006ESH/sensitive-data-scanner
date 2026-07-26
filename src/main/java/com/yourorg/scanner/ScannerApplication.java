package com.yourorg.scanner;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Entry point for the Sensitive Data Scanner application.
 * <p>
 * Enables Spring's scheduling support so that {@code @Scheduled} cron jobs
 * (see {@code scheduler.ScanScheduler}) can trigger periodic drive scans.
 */
@SpringBootApplication
@EnableScheduling
public class ScannerApplication {

    public static void main(String[] args) {
        SpringApplication.run(ScannerApplication.class, args);
    }
}