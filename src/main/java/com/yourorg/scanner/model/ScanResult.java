package com.yourorg.scanner.model;

import java.time.LocalDateTime;

/**
 * A single confirmed finding: one sensitive value detected, validated, and
 * masked in one file. This is the object that ultimately becomes one row
 * in the scan report (CSV/Excel) and one row in the web dashboard.
 */
public class ScanResult {

    private final String fileName;
    private final String filePath;
    private final SensitiveDataType dataType;
    private final RiskLevel riskLevel;
    private final String maskedValue;
    private final LocalDateTime scanTimestamp;

    public ScanResult(String fileName, String filePath, SensitiveDataType dataType,
                      RiskLevel riskLevel, String maskedValue, LocalDateTime scanTimestamp) {
        this.fileName = fileName;
        this.filePath = filePath;
        this.dataType = dataType;
        this.riskLevel = riskLevel;
        this.maskedValue = maskedValue;
        this.scanTimestamp = scanTimestamp;
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
}