package com.yourorg.scanner.report;

import org.springframework.stereotype.Component;

import java.util.Map;


@Component
public class ReportWriterFactory {

    private final Map<String, ReportGenerator> generatorsByFormat;

    public ReportWriterFactory(CsvReportGenerator csvGenerator, ExcelReportGenerator excelGenerator) {
        this.generatorsByFormat = Map.of(
                "csv", csvGenerator,
                "excel", excelGenerator
        );
    }


    public ReportGenerator getGenerator(String format) {
        if (format == null) {
            return null;
        }
        return generatorsByFormat.get(format.toLowerCase());
    }
}