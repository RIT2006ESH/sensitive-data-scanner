package com.yourorg.scanner.extractor;

import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

@Component
public class XlsxTextExtractor implements TextExtractor {

    @Override
    public String extractText(Path filePath) throws IOException {
        StringBuilder text = new StringBuilder();

        try (InputStream in = Files.newInputStream(filePath);
             XSSFWorkbook workbook = new XSSFWorkbook(in)) {

            for (int i = 0; i < workbook.getNumberOfSheets(); i++) {
                XSSFSheet sheet = workbook.getSheetAt(i);
                for (Row row : sheet) {
                    for (Cell cell : row) {
                        text.append(cell.toString()).append(" ");
                    }
                    text.append(System.lineSeparator());
                }
            }
        }
        return text.toString();
    }
}