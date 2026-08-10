package com.yourorg.scanner.validator;

import org.springframework.stereotype.Component;


@Component
public class AadhaarChecksumValidator {

    // Verhoeff multiplication table
    private static final int[][] MULTIPLICATION_TABLE = {
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
            {1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
            {2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
            {3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
            {4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
            {5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
            {6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
            {7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
            {8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
            {9, 8, 7, 6, 5, 4, 3, 2, 1, 0}
    };

    // Verhoeff permutation table
    private static final int[][] PERMUTATION_TABLE = {
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
            {1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
            {5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
            {8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
            {9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
            {4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
            {2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
            {7, 0, 4, 6, 9, 1, 3, 2, 5, 8}
    };


    public boolean isValid(String rawCandidate) {
        String digitsOnly = stripNonDigits(rawCandidate);

        if (digitsOnly.length() != 12) {
            return false;
        }

        int checksum = 0;
        int length = digitsOnly.length();

        for (int i = 0; i < length; i++) {
            int digit = digitsOnly.charAt(length - 1 - i) - '0';
            checksum = MULTIPLICATION_TABLE[checksum][PERMUTATION_TABLE[i % 8][digit]];
        }

        return checksum == 0;
    }

    private String stripNonDigits(String input) {
        return input == null ? "" : input.replaceAll("[^0-9]", "");
    }
}