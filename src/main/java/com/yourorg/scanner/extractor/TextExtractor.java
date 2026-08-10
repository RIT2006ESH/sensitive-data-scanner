package com.yourorg.scanner.extractor;

import java.io.IOException;
import java.nio.file.Path;


public interface TextExtractor {


    String extractText(Path filePath) throws IOException;
}