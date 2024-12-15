package com.hideakin.mycrypto.constant;

public enum OperationalMode {

	UNDEFINED("", ""),
	CBC("CBC", "Cipher Block Chaining"),
	ECB("ECB", "Electronic CodeBook"),
	CFB8("CFB8", "8-bit Cipher FeedBack Mode"),
	OFB8("OFB8", "8-bit Output FeedBack Mode"),
	GCM("GCM", "Galois/Counter Mode");

	private String _label;
	private String _description;

	private OperationalMode(String label, String description) {
		_label = label;
		_description = description;
	}

	public String label() {
		return _label;
	}

	public String description() {
		return _description;
	}

}
