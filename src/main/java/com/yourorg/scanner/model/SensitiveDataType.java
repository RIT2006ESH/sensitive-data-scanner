package com.yourorg.scanner.model;

/**
 * The categories of sensitive data this scanner is able to detect.
 * Adding a new type later (e.g. PASSPORT_NUMBER) means adding a value here
 * plus a matching detector — nothing else in the pipeline needs to change.
 */
public enum SensitiveDataType {
    CARD_NUMBER,
    PAN_NUMBER,
    AADHAAR_NUMBER
}