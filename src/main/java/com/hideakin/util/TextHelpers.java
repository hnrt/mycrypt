package com.hideakin.util;

public class TextHelpers {

	public static String numberOfBytes(long count) {
		return String.format("%d %s", count, count > 1 ? "bytes" : "byte");
	}

	public static final String SP10 = "          ";

	public static String whitespaces(int length) {
		StringBuilder s = new StringBuilder();
		while (length >= 10) {
			s.append(SP10);
			length -= 10;
		}
		while (length > 0) {
			s.append(' ');
			length--;
		}
		return s.toString();
	}

}
