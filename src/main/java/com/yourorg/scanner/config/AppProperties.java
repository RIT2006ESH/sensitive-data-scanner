package com.yourorg.scanner.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@ConfigurationProperties(prefix = "scanner")
public class AppProperties {

    /** Drives/root folders to scan recursively, e.g. C:\, D:\ */
    private List<String> targetDrives;

    /** File extensions eligible for extraction, e.g. pdf, docx, xlsx, txt, csv */
    private List<String> supportedExtensions;

    /** Folders to skip entirely during the scan */
    private List<String> excludedPaths;

    /** Cron expression controlling how often the scan runs */
    private String scheduleCron;

    /** Report output settings */
    private Report report = new Report();

    public static class Report {
        private String outputDirectory;
        private String format;

        public String getOutputDirectory() {
            return outputDirectory;
        }

        public void setOutputDirectory(String outputDirectory) {
            this.outputDirectory = outputDirectory;
        }

        public String getFormat() {
            return format;
        }

        public void setFormat(String format) {
            this.format = format;
        }
    }

    public List<String> getTargetDrives() {
        return targetDrives;
    }

    public void setTargetDrives(List<String> targetDrives) {
        this.targetDrives = targetDrives;
    }

    public List<String> getSupportedExtensions() {
        return supportedExtensions;
    }

    public void setSupportedExtensions(List<String> supportedExtensions) {
        this.supportedExtensions = supportedExtensions;
    }

    public List<String> getExcludedPaths() {
        return excludedPaths;
    }

    public void setExcludedPaths(List<String> excludedPaths) {
        this.excludedPaths = excludedPaths;
    }

    public String getScheduleCron() {
        return scheduleCron;
    }

    public void setScheduleCron(String scheduleCron) {
        this.scheduleCron = scheduleCron;
    }

    public Report getReport() {
        return report;
    }

    public void setReport(Report report) {
        this.report = report;
    }
}