package com.yourorg.scanner.extractor;

import org.springframework.stereotype.Component;

import java.util.Map;


@Component
public class ExtractorFactory {

    private final Map<String, TextExtractor> extractorsByExtension;

    public ExtractorFactory(PdfTextExtractor pdfExtractor,
                            DocxTextExtractor docxExtractor,
                            XlsxTextExtractor xlsxExtractor,
                            TxtTextExtractor txtExtractor,
                            CsvTextExtractor csvExtractor) {
        this.extractorsByExtension = Map.of(
                "pdf", pdfExtractor,
                "docx", docxExtractor,
                "xlsx", xlsxExtractor,
                "txt", txtExtractor,
                "csv", csvExtractor
        );
    }

    /**
     * @param extension file extension without the dot, e.g. "pdf" (case-insensitive)
     * @return the matching extractor, or null if the extension is unsupported
     */
    public TextExtractor getExtractor(String extension) {
        if (extension == null) {
            return null;
        }
        return extractorsByExtension.get(extension.toLowerCase());
    }
}