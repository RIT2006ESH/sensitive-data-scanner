package com.yourorg.scanner.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@ConfigurationProperties(prefix = "scanner")
public class AppProperties {

    private List<String> targetDrives;
    private List<String> supportedExtensions;
    private List<String> excludedPaths;
    private List<String> excludedFolderNames;
    private String scheduleCron;
    private Report report = new Report();

    private int concurrency = 0;

    public static class Report {
        private String outputDirectory;
        private String format;

        public String getOutputDirectory() { return outputDirectory; }
        public void setOutputDirectory(String outputDirectory) { this.outputDirectory = outputDirectory; }
        public String getFormat() { return format; }
        public void setFormat(String format) { this.format = format; }
    }

    public List<String> getTargetDrives() { return targetDrives; }
    public void setTargetDrives(List<String> targetDrives) { this.targetDrives = targetDrives; }
    public List<String> getSupportedExtensions() { return supportedExtensions; }
    public void setSupportedExtensions(List<String> supportedExtensions) { this.supportedExtensions = supportedExtensions; }
    public List<String> getExcludedPaths() { return excludedPaths; }
    public void setExcludedPaths(List<String> excludedPaths) { this.excludedPaths = excludedPaths; }
    public List<String> getExcludedFolderNames() { return excludedFolderNames; }
    public void setExcludedFolderNames(List<String> excludedFolderNames) { this.excludedFolderNames = excludedFolderNames; }
    public String getScheduleCron() { return scheduleCron; }
    public void setScheduleCron(String scheduleCron) { this.scheduleCron = scheduleCron; }
    public Report getReport() { return report; }
    public void setReport(Report report) { this.report = report; }
    public int getConcurrency() { return concurrency; }
    public void setConcurrency(int concurrency) { this.concurrency = concurrency; }
}