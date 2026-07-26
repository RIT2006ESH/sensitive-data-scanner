package com.yourorg.scanner.extractor;

import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

@Component
public class TxtTextExtractor implements TextExtractor {

    @Override
    public String extractText(Path filePath) throws IOException {
        return Files.readString(filePath);
    }
}