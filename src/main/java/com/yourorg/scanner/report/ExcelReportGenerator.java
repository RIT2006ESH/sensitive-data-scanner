package com.yourorg.scanner.report;

import com.yourorg.scanner.model.ScanResult;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellStyle;
import org.apache.poi.ss.usermodel.Font;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.stereotype.Component;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Component
public class ExcelReportGenerator implements ReportGenerator {

    private static final String[] HEADERS = {
            "File Name", "File Path", "Sensitive Data Type", "Masked Value", "Scan Timestamp"
    };

    private static final DateTimeFormatter TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @Override
    public Path generateReport(List<ScanResult> findings, Path outputDirectory) throws IOException {
        Files.createDirectories(outputDirectory);

        String fileName = "scan-report-" + System.currentTimeMillis() + ".xlsx";
        Path reportPath = outputDirectory.resolve(fileName);

        try (XSSFWorkbook workbook = new XSSFWorkbook()) {
            XSSFSheet sheet = workbook.createSheet("Scan Results");

            writeHeaderRow(workbook, sheet);
            writeDataRows(sheet, findings);
            autoSizeColumns(sheet);

            try (OutputStream out = new FileOutputStream(reportPath.toFile())) {
                workbook.write(out);
            }
        }

        return reportPath;
    }

    private void writeHeaderRow(XSSFWorkbook workbook, XSSFSheet sheet) {
        Font boldFont = workbook.createFont();
        boldFont.setBold(true);

        CellStyle headerStyle = workbook.createCellStyle();
        headerStyle.setFont(boldFont);

        Row headerRow = sheet.createRow(0);
        for (int col = 0; col < HEADERS.length; col++) {
            Cell cell = headerRow.createCell(col);
            cell.setCellValue(HEADERS[col]);
            cell.setCellStyle(headerStyle);
        }
    }

    private void writeDataRows(XSSFSheet sheet, List<ScanResult> findings) {
        int rowIndex = 1;
        for (ScanResult result : findings) {
            Row row = sheet.createRow(rowIndex++);
            row.createCell(0).setCellValue(result.getFileName());
            row.createCell(1).setCellValue(result.getFilePath());
            row.createCell(2).setCellValue(result.getDataType().name());
            row.createCell(3).setCellValue(result.getMaskedValue());
            row.createCell(4).setCellValue(result.getScanTimestamp().format(TIMESTAMP_FORMAT));
        }
    }

    private void autoSizeColumns(XSSFSheet sheet) {
        for (int col = 0; col < HEADERS.length; col++) {
            sheet.autoSizeColumn(col);
        }
    }
}