package dev.sbomscope.bump;

/** A half-open byte range in one file's UTF-8 bytes, with the 1-based line/column of its start. */
public record TextRange(int start, int end, int line, int column) {}
