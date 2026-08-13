package com.yourorg.scanner.detector;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CardNumberDetectorTest {

    private final CardNumberDetector detector = new CardNumberDetector();

    @Test
    void detectsUnbrokenSixteenDigitNumber() {
        List<String> results = detector.detectCandidates("Card: 4539578763621486 on file.");
        assertEquals(1, results.size());
        assertEquals("4539578763621486", results.get(0));
    }

    @Test
    void detectsStandardFourBlockGrouping() {
        List<String> results = detector.detectCandidates("Number: 4111 1111 1111 1111 please charge.");
        assertEquals(1, results.size());
        assertEquals("4111 1111 1111 1111", results.get(0));
    }

    @Test
    void detectsHyphenGroupedNumber() {
        List<String> results = detector.detectCandidates("4532-0151-1283-0366");
        assertEquals(1, results.size());
    }

    @Test
    void doesNotMatchShortUnrelatedNumbersSeparatedBySpaces() {
        List<String> results = detector.detectCandidates("122 6 148 72 35 0 33 6 45");
        assertTrue(results.isEmpty(), "Should not match loosely-spaced short numbers as a card number");
    }

    @Test
    void doesNotMatchTooShortNumber() {
        List<String> results = detector.detectCandidates("12345");
        assertTrue(results.isEmpty());
    }

    @Test
    void doesNotMatchTooLongNumber() {
        List<String> results = detector.detectCandidates("12345678901234567890123");
        assertTrue(results.isEmpty());
    }
}
