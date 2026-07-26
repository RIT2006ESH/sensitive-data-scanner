package com.yourorg.scanner.extractor;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;

@Component
public class CsvTextExtractor implements TextExtractor {

    @Override
    public String extractText(Path filePath) throws IOException {
        StringBuilder text = new StringBuilder();

        try (Reader reader = Files.newBufferedReader(filePath);
             CSVParser parser = CSVFormat.DEFAULT.parse(reader)) {

            for (CSVRecord record : parser) {
                for (String value : record) {
                    text.append(value).append(" ");
                }
                text.append(System.lineSeparator());
            }
        }
        return text.toString();
    }
}