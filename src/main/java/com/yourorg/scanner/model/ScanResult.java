package com.yourorg.scanner.model;

import java.time.LocalDateTime;


public class ScanResult {

    private final String fileName;
    private final String filePath;
    private final SensitiveDataType dataType;
    private final RiskLevel riskLevel;
    private final String maskedValue;
    private final LocalDateTime scanTimestamp;
    private final LocalDateTime fileCreationTime;
    private final LocalDateTime fileModifiedTime;

    public ScanResult(String fileName, String filePath, SensitiveDataType dataType,
                      RiskLevel riskLevel, String maskedValue, LocalDateTime scanTimestamp,
                      LocalDateTime fileCreationTime, LocalDateTime fileModifiedTime) {
        this.fileName = fileName;
        this.filePath = filePath;
        this.dataType = dataType;
        this.riskLevel = riskLevel;
        this.maskedValue = maskedValue;
        this.scanTimestamp = scanTimestamp;
        this.fileCreationTime = fileCreationTime;
        this.fileModifiedTime = fileModifiedTime;
    }

    public String getFileName() {
        return fileName;
    }

    public String getFilePath() {
        return filePath;
    }

    public SensitiveDataType getDataType() {
        return dataType;
    }

    public RiskLevel getRiskLevel() {
        return riskLevel;
    }

    public String getMaskedValue() {
        return maskedValue;
    }

    public LocalDateTime getScanTimestamp() {
        return scanTimestamp;
    }

    public LocalDateTime getFileCreationTime() {
        return fileCreationTime;
    }

    public LocalDateTime getFileModifiedTime() {
        return fileModifiedTime;
    }
}
