package com.hideakin.mycrypto.constant;

public enum Padding {

	UNDEFINED("", ""),
	NONE("NoPadding", "None"),
	PKCS5("PKCS5Padding", "PKCS5");

	private String _label;
	private String _description;

	private Padding(String label, String description) {
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
