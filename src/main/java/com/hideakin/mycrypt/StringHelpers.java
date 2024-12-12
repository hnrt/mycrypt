package com.hideakin.mycrypt;

public class StringHelpers {

	public static String numberOfBytes(long count) {
		return String.format("%d %s", count, count > 1 ? "bytes" : "byte");
	}

	public static String whitespaces(int length) {
		StringBuilder s = new StringBuilder();
		while (length > 10) {
			s.append("          ");
			length -= 10;
		}
		while (length > 0) {
			s.append(' ');
			length--;
		}
		return s.toString();
	}

}
