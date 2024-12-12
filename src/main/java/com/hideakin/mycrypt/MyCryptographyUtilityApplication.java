package com.hideakin.mycrypt;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MyCryptographyUtilityApplication {

	public static final String VERSION = "0.3.0";

	public static final String DESCRIPTION = "My Cryptography Utility version %s\n";

	public static final String SHA_256 = "SHA-256";

	public static final String AES_CBC_PKCS5PADDING = "AES/CBC/PKCS5Padding";
	public static final String AES_ECB_PKCS5PADDING = "AES/ECB/PKCS5Padding";
	public static final String AES_CFB8_NOPADDING = "AES/CFB8/NoPadding";
	public static final String AES_OFB8_NOPADDING = "AES/OFB8/NoPadding";

	public static final int FLAG_HELP = 1 << 0;
	public static final int FLAG_OVERWRITE = 1 << 1;
	public static final int FLAG_IN_TO_CLOSE = 1 << 4;
	public static final int FLAG_OUT_TO_CLOSE = 1 << 5;
	public static final int FLAG_INFO_TO_PRINT = 1 << 6;

	private String _transformation;
	private int _keyLength = 0;
	private int _ivLength = 0;
	private String _keyPhrase;
	private String _ivPhrase;
	private byte[] _key;
	private byte[] _iv;
	private String _inFileName;
	private String _outFileName;
	private int _mode = 0;
	private int _flags = 0;

	public MyCryptographyUtilityApplication() {
	}

	private void setTransformation(String value) {
		if (_transformation != null) {
			throw new RuntimeException("Algorithm is specified more than once.");
		}
		_transformation = value;
	}

	private void setKeyLength(int value) {
		_keyLength = value;
	}

	private void setIvLength(int value) {
		_ivLength = value;
	}

	private void setKey(String value) {
		_key = HexString.parse(value);
	}

	private void setIv(String value) {
		_iv = HexString.parse(value);
	}

	private void setKeyPhrase(String value) {
		_keyPhrase = value;
	}

	private void setIvPhrase(String value) {
		_ivPhrase = value;
	}

	private void setInputPath(int mode, String value) {
		_mode = mode;
		_inFileName = value;
	}

	private void setOutputPath(String value) {
		_outFileName = value;
	}
	
	private void setFlags(int value) {
		_flags |= value;
	}
	
	private boolean checkFlags(int value) {
		return (_flags & value) == value;
	}

	private boolean canOverwrite() {
		return checkFlags(FLAG_OVERWRITE);
	}

	private boolean canPrintInfo() {
		return checkFlags(FLAG_INFO_TO_PRINT);
	}

	private boolean mustCloseInput() {
		return checkFlags(FLAG_IN_TO_CLOSE);
	}

	private boolean mustCloseOutput() {
		return checkFlags(FLAG_OUT_TO_CLOSE);
	}

	public void run() throws Exception {
		verifyParameters();
		verifyKey();
		verifyIv();
		InputStream in = null;
		OutputStream out = null;
		try {
			in = openInput();
			out = openOutput();
			Cipher cipher = getCipher();
			long inBytes = 0L;
			long outBytes = 0L;
			byte[] buf = new byte[8192];
			int n;
			while ((n = in.read(buf)) >= 0) {
				if (n > 0) {
					inBytes += n;
					byte[] result = cipher.update(buf, 0, n);
					if (result != null) {
						out.write(result);
						outBytes += result.length;
					}
				}
			}
			if (canPrintInfo()) {
				System.out.printf("%s in\n", StringHelpers.numberOfBytes(inBytes));
			}
			byte[] result = cipher.doFinal();
			if (result != null) {
				out.write(result);
				outBytes += result.length;
			}
			out.flush();
			if (canPrintInfo()) {
				System.out.printf("%s out\n", StringHelpers.numberOfBytes(outBytes));
			}
		} finally {
			closeOutput(out);
			closeInput(in);
		}
	}

	private void verifyParameters() {
		if (_transformation == null) {
			throw new RuntimeException("Algorithm is not specified.");
		}
		if (_mode == 0) {
			throw new RuntimeException("Mode(encrypt/decrypt) is not specified.");
		}
		if (_outFileName == null) {
			throw new RuntimeException("Output file is not specified.");
		}
	}

	private void verifyKey() throws Exception {
		if (_key == null) {
			if (_keyPhrase == null) {
				throw new RuntimeException("Neither key nor passphrase is specified. Specify either one.");
			}
			MessageDigest md = MessageDigest.getInstance(SHA_256);
			_key = md.digest(_keyPhrase.getBytes());
		} else if (_keyPhrase != null) {
			throw new RuntimeException("Both key and passphrase are specified. Specify either one.");
		}
		if (_key.length != _keyLength) {
			_key = Arrays.copyOf(_key, _keyLength);
		}
	}

	private void verifyIv() throws Exception {
		if (_ivLength > 0) {
			if (_iv == null) {
				if (_ivPhrase == null) {
					throw new RuntimeException("Neither IV nor IV-hint is specified. Specify either one.");
				}
				MessageDigest md = MessageDigest.getInstance(SHA_256);
				_iv = md.digest(_ivPhrase.getBytes());
			} else if (_ivPhrase != null) {
				throw new RuntimeException("Both IV and IV-hint are specified. Specify either one.");
			}
			if (_ivLength > 0 && _iv.length != _ivLength) {
				_iv = Arrays.copyOf(_iv, _ivLength);
			}
		} else if (_iv != null) {
			if (_ivPhrase != null) {
				throw new RuntimeException("Both IV and IV-hint are specified. Do not specify both.");
			} else {
				throw new RuntimeException("IV is specified. Do not specify it.");
			}
		} else if (_ivPhrase != null) {
			throw new RuntimeException("IV-hint is specified. Do not specify it.");
		}
	}

	private InputStream openInput() throws Exception {
		InputStream in;
		if ("-".equals(_inFileName)) {
			in = System.in;
		} else {
			Path path = Paths.get(_inFileName);
			if (!Files.exists(path)) {
				throw new RuntimeException("Input file does not exist.");
			}
			in = Files.newInputStream(path);
			setFlags(FLAG_IN_TO_CLOSE);
		}
		return in;
	}
	
	private void closeInput(InputStream in) throws Exception {
		if (mustCloseInput()) {
			try {
				in.close();
			} catch (Exception e) {
			}
		}
	}

	private OutputStream openOutput() throws Exception {
		OutputStream out;
		if ("-".equals(_outFileName)) {
			out = System.out;
		} else {
			Path path = Paths.get(_outFileName);
			if (!canOverwrite() && Files.exists(path)) {
				throw new RuntimeException("Output file already exists.");
			}
			out = Files.newOutputStream(path);
			setFlags(FLAG_OUT_TO_CLOSE | FLAG_INFO_TO_PRINT);
		}
		return out;
	}
	
	private void closeOutput(OutputStream out) throws Exception {
		if (mustCloseOutput()) {
			try {
				out.close();
			} catch (Exception e) {
			}
		}
	}

	private Cipher getCipher() throws Exception {
		Cipher cipher = Cipher.getInstance(_transformation);
		if (_ivLength > 0) {
			SecretKeySpec keySpec = new SecretKeySpec(_key, algorithm());
			IvParameterSpec ivSpec = new IvParameterSpec(_iv);
			cipher.init(_mode, keySpec, ivSpec);
			if (canPrintInfo()) {
				System.out.printf("KEY %s\n", HexString.toString(_key));
				System.out.printf(" IV %s\n", HexString.toString(_iv));
			}
		} else {
			SecretKeySpec keySpec = new SecretKeySpec(_key, algorithm());
			cipher.init(_mode, keySpec);
			if (canPrintInfo()) {
				System.out.printf("KEY %s\n", HexString.toString(_key));
			}
		}
		return cipher;
	}

	private String algorithm() {
		return _transformation.split("/")[0];
	}

	public CommandLineParameters commandLineParameters() {
		return (new CommandLineParameters())
				.add("aes-256-cbc", transformationDescription(AES_CBC_PKCS5PADDING, 256), (p) -> {
					setTransformation(AES_CBC_PKCS5PADDING);
					setKeyLength(256 / 8);
					setIvLength(16);
					return true;
				})
				.add("aes-192-cbc", transformationDescription(AES_CBC_PKCS5PADDING, 192), (p) -> {
					setTransformation(AES_CBC_PKCS5PADDING);
					setKeyLength(192 / 8);
					setIvLength(16);
					return true;
				})
				.add("aes-128-cbc", transformationDescription(AES_CBC_PKCS5PADDING, 128), (p) -> {
					setTransformation(AES_CBC_PKCS5PADDING);
					setKeyLength(128 / 8);
					setIvLength(16);
					return true;
				})
				.add("aes-256-ecb", transformationDescription(AES_ECB_PKCS5PADDING, 256), (p) -> {
					setTransformation(AES_ECB_PKCS5PADDING);
					setKeyLength(256 / 8);
					return true;
				})
				.add("aes-192-ecb", transformationDescription(AES_ECB_PKCS5PADDING, 192), (p) -> {
					setTransformation(AES_ECB_PKCS5PADDING);
					setKeyLength(192 / 8);
					return true;
				})
				.add("aes-128-ecb", transformationDescription(AES_ECB_PKCS5PADDING, 128), (p) -> {
					setTransformation(AES_ECB_PKCS5PADDING);
					setKeyLength(128 / 8);
					return true;
				})
				.add("aes-256-cfb", transformationDescription(AES_CFB8_NOPADDING, 256), (p) -> {
					setTransformation(AES_CFB8_NOPADDING);
					setKeyLength(256 / 8);
					setIvLength(16);
					return true;
				})
				.add("aes-192-cfb", transformationDescription(AES_CFB8_NOPADDING, 192), (p) -> {
					setTransformation(AES_CFB8_NOPADDING);
					setKeyLength(192 / 8);
					setIvLength(16);
					return true;
				})
				.add("aes-128-cfb", transformationDescription(AES_CFB8_NOPADDING, 128), (p) -> {
					setTransformation(AES_CFB8_NOPADDING);
					setKeyLength(128 / 8);
					setIvLength(16);
					return true;
				})
				.add("aes-256-ofb", transformationDescription(AES_OFB8_NOPADDING, 256), (p) -> {
					setTransformation(AES_OFB8_NOPADDING);
					setKeyLength(256 / 8);
					setIvLength(16);
					return true;
				})
				.add("aes-192-ofb", transformationDescription(AES_OFB8_NOPADDING, 192), (p) -> {
					setTransformation(AES_OFB8_NOPADDING);
					setKeyLength(192 / 8);
					setIvLength(16);
					return true;
				})
				.add("aes-128-ofb", transformationDescription(AES_OFB8_NOPADDING, 128), (p) -> {
					setTransformation(AES_OFB8_NOPADDING);
					setKeyLength(128 / 8);
					setIvLength(16);
					return true;
				})
				.add("-encrypt", "PATH", "encrypts file\n(a hyphen represents the standard input)", (p) -> {
					if (p.next()) {
						setInputPath(Cipher.ENCRYPT_MODE, p.argument());
						return true;
					} else {
						throw new RuntimeException("Input file is not specified.");
					}
				})
				.add("-decrypt", "PATH", "decrypts file\n(a hyphen represents the standard input)", (p) -> {
					if (p.next()) {
						setInputPath(Cipher.DECRYPT_MODE, p.argument());
						return true;
					} else {
						throw new RuntimeException("Input file is not specified.");
					}
				})
				.add("-out", "PATH", "specifies output file\n(a hyphen represents the standard output)", (p) -> {
					if (p.next()) {
						setOutputPath(p.argument());
						return true;
					} else {
						throw new RuntimeException("Output file is not specified.");
					}
				})
				.add("-key", "HEXSTRING", "specifies private key", (p) -> {
					if (p.next()) {
						setKey(p.argument());
						return true;
					} else {
						throw new RuntimeException("Private key is not specified.");
					}
				})
				.add("-iv", "HEXSTRING", "specifies initial vector", (p) -> {
					if (p.next()) {
						setIv(p.argument());
						return true;
					} else {
						throw new RuntimeException("Initial vector is not specified.");
					}
				})
				.add("-keyphrase", "TEXT", "specifies text phrase to generate private key", (p) -> {
					if (p.next()) {
						setKeyPhrase(p.argument());
						return true;
					} else {
						throw new RuntimeException("Key phrase is not specified.");
					}
				})
				.add("-ivphrase", "TEXT", "specifies text phrase to generate initial vector", (p) -> {
					if (p.next()) {
						setIvPhrase(p.argument());
						return true;
					} else {
						throw new RuntimeException("IV phrase is not specified.");
					}
				})
				.add("-overwrite", "writes to output file even if it already exists", (p) -> {
					setFlags(FLAG_OVERWRITE);
					return true;
				})
				.add("-help", "prints this message", (p) -> {
					setFlags(FLAG_HELP);
					return false;
				})
				.addAlias("-e", "-encrypt")
				.addAlias("-d", "-decrypt")
				.addAlias("-o", "-out")
				.addAlias("-k", "-key")
				.addAlias("-i", "-iv")
				.addAlias("-K", "-keyphrase")
				.addAlias("-I", "-ivphrase")
				.addAlias("-h", "-help");
	}

	private static String transformationDescription(String transformation, int keyBits) {
		String[] ss = transformation.split("/");
		return String.format("%s %s mode %s %d-bit-key", ss[0], ss[1], ss[2], keyBits);
	}

	public static void main(String[] args) {
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		try {
			CommandLineParameters parameters = app.commandLineParameters();
			parameters.process(args);
			if (args.length == 0 || app.checkFlags(FLAG_HELP)) {
				System.out.printf(DESCRIPTION, VERSION);
				System.out.printf("%s", parameters);
			} else {
				app.run();
			}
			System.exit(0);
		} catch (Throwable t) {
			System.err.printf("ERROR: %s\n", t.getMessage());
			while ((t = t.getCause()) != null) {
				System.err.printf("       %s\n", t.getMessage());
			}
			System.exit(1);
		}
	}

}
