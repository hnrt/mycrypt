package com.hideakin.mycrypto.constant;

public enum Algorithm {

	UNDEFINED(""),
	AES("AES");

	private String _label;

	private Algorithm(String label) {
		_label = label;
	}

	public String label() {
		return _label;
	}

}
