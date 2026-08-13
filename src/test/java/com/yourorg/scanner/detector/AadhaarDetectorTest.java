package com.yourorg.scanner.detector;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AadhaarDetectorTest {

    private final AadhaarDetector detector = new AadhaarDetector();

    @Test
    void detectsUnbrokenTwelveDigitStartingWithValidDigit() {
        List<String> results = detector.detectCandidates("Aadhaar: 234123412346 on record.");
        assertEquals(1, results.size());
        assertEquals("234123412346", results.get(0));
    }

    @Test
    void detectsSpaceGroupedNumber() {
        List<String> results = detector.detectCandidates("2341 2341 2346");
        assertEquals(1, results.size());
    }

    @Test
    void doesNotMatchNumberStartingWithZero() {
        List<String> results = detector.detectCandidates("034123412346");
        assertTrue(results.isEmpty());
    }

    @Test
    void doesNotMatchNumberStartingWithOne() {
        List<String> results = detector.detectCandidates("134123412346");
        assertTrue(results.isEmpty());
    }

    @Test
    void doesNotMatchElevenDigitNumber() {
        List<String> results = detector.detectCandidates("23412341234");
        assertTrue(results.isEmpty());
    }
}
