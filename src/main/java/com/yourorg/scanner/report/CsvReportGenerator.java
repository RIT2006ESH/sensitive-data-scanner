package com.yourorg.scanner.report;

import com.yourorg.scanner.model.ScanResult;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Component
public class CsvReportGenerator implements ReportGenerator {

    private static final DateTimeFormatter TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @Override
    public Path generateReport(List<ScanResult> findings, Path outputDirectory) throws IOException {
        Files.createDirectories(outputDirectory);

        String fileName = "scan-report-" + System.currentTimeMillis() + ".csv";
        Path reportPath = outputDirectory.resolve(fileName);

        CSVFormat format = CSVFormat.DEFAULT.builder()
                .setHeader("File Name", "File Path", "Sensitive Data Type", "Risk Level", "Masked Value",
                        "Scan Timestamp", "File Created", "File Modified")
                .build();

        try (Writer writer = Files.newBufferedWriter(reportPath);
             CSVPrinter printer = new CSVPrinter(writer, format)) {

            for (ScanResult result : findings) {
                printer.printRecord(
                        result.getFileName(),
                        result.getFilePath(),
                        result.getDataType(),
                        result.getRiskLevel(),
                        result.getMaskedValue(),
                        result.getScanTimestamp().format(TIMESTAMP_FORMAT),
                        result.getFileCreationTime() == null ? "" : result.getFileCreationTime().format(TIMESTAMP_FORMAT),
                        result.getFileModifiedTime() == null ? "" : result.getFileModifiedTime().format(TIMESTAMP_FORMAT)
                );
            }
        }

        return reportPath;
    }
}
