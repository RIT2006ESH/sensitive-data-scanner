package com.yourorg.scanner.report;

import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Picks the correct ReportGenerator based on the configured report format
 * (scanner.report.format in application.yml — "csv" or "excel").
 */
@Component
public class ReportWriterFactory {

    private final Map<String, ReportGenerator> generatorsByFormat;

    public ReportWriterFactory(CsvReportGenerator csvGenerator, ExcelReportGenerator excelGenerator) {
        this.generatorsByFormat = Map.of(
                "csv", csvGenerator,
                "excel", excelGenerator
        );
    }

    /**
     * @param format "csv" or "excel" (case-insensitive)
     * @return the matching generator, or null if the format is unsupported
     */
    public ReportGenerator getGenerator(String format) {
        if (format == null) {
            return null;
        }
        return generatorsByFormat.get(format.toLowerCase());
    }
}