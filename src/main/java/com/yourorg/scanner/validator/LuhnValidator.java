package com.yourorg.scanner.validator;

import org.springframework.stereotype.Component;

/**
 * Validates card numbers using the Luhn (mod-10) checksum algorithm.
 * This is the standard check used by Visa, Mastercard, Amex, etc. to
 * catch typos/random digit sequences before they're even sent to a bank.
 */
@Component
public class LuhnValidator {

    /**
     * @param rawCandidate the candidate string as found by the detector
     *                     (may contain spaces/hyphens)
     * @return true if the digits form a Luhn-valid number
     */
    public boolean isValid(String rawCandidate) {
        String digitsOnly = stripNonDigits(rawCandidate);

        if (digitsOnly.length() < 13 || digitsOnly.length() > 19) {
            return false;
        }

        int sum = 0;
        boolean doubleDigit = false;

        for (int i = digitsOnly.length() - 1; i >= 0; i--) {
            int digit = digitsOnly.charAt(i) - '0';

            if (doubleDigit) {
                digit *= 2;
                if (digit > 9) {
                    digit -= 9;
                }
            }

            sum += digit;
            doubleDigit = !doubleDigit;
        }

        return sum % 10 == 0;
    }

    private String stripNonDigits(String input) {
        return input == null ? "" : input.replaceAll("[^0-9]", "");
    }
}