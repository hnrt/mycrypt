package com.hideakin.mycrypt;

import java.util.Arrays;

public class HexString {

	public static byte[] parse(String value) {
		byte[] buf = new byte[value.length() / 2];
		int i = 0;
		int j = 0;
		while (j < value.length()) {
			char c = value.charAt(j++);
			int d;
			if ('0' <= c && c <= '9') {
				d = c - '0';
			} else if ('A' <= c && c <= 'F') {
				d = 10 + c - 'A';
			} else if ('a' <= c && c <= 'f') {
				d = 10 + c - 'a';
			} else {
				continue;
			}
			if (j == value.length()) {
				throw new RuntimeException(String.format("Parse error at %d: %s", j - 1, value));
			}
			c = value.charAt(j++);
			if ('0' <= c && c <= '9') {
				d = d * 16 + c - '0';
			} else if ('A' <= c && c <= 'F') {
				d = d * 16 + 10 + c - 'A';
			} else if ('a' <= c && c <= 'f') {
				d = d * 16 + 10 + c - 'a';
			} else {
				throw new RuntimeException(String.format("Parse error at %d: %s", j - 1, value));
			}
			buf[i++] = (byte)d;
		}
		if (i < buf.length) {
			buf = Arrays.copyOf(buf, i);
		}
		return buf;
	}

	private static final char[] TEXT = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

	public static String toString(byte[] value) {
		StringBuilder s = new StringBuilder();
		for (byte b : value) {
			s.append(TEXT[(b >> 4) & 0xF]);
			s.append(TEXT[(b >> 0) & 0xF]);
		}
		return s.toString();
	}

}
