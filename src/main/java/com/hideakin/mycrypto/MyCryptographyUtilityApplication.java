package com.hideakin.mycrypto;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.hideakin.util.CommandLineParameters;
import com.hideakin.util.HexString;
import com.hideakin.util.TextHelpers;

public class MyCryptographyUtilityApplication {

	public static final String VERSION = "0.4.0";

	public static final String DESCRIPTION = "My Cryptography Utility version %s\n";

	private static final String SHA_256 = "SHA-256";

	private static final String AES_CBC_PKCS5PADDING = "AES/CBC/PKCS5Padding";
	private static final String AES_ECB_PKCS5PADDING = "AES/ECB/PKCS5Padding";
	private static final String AES_CFB8_NOPADDING = "AES/CFB8/NoPadding";
	private static final String AES_OFB8_NOPADDING = "AES/OFB8/NoPadding";
	private static final String AES_GCM_NOPADDING = "AES/GCM/NoPadding";

	private static final int AES_256_KEY_LENGTH = 256 / 8;
	private static final int AES_192_KEY_LENGTH = 192 / 8;
	private static final int AES_128_KEY_LENGTH = 128 / 8;
	private static final int AES_IV_LENGTH = 16;
	private static final int AES_GCM_NONCE_LENGTH = 12;
	private static final int AES_GCM_TAG_LENGTH_MIN = 12;
	private static final int AES_GCM_TAG_LENGTH_MAX = 16;
	
	private static final int FLAG_OVERWRITE = 1 << 0;
	private static final int FLAG_IN_TO_CLOSE = 1 << 4;
	private static final int FLAG_OUT_TO_CLOSE = 1 << 5;
	private static final int FLAG_INFO_TO_PRINT = 1 << 6;

	private String _transformation;
	private int _keyLength = 0;
	private int _ivLength = 0;
	private int _nonceLength = 0;
	private int _tagLength = 0;
	private byte[] _key;
	private byte[] _iv;
	private byte[] _nonce;
	private byte[] _aad; // Additional Authentication Data
	private String _inFileName;
	private String _outFileName;
	private int _operation = 0;
	private int _flags = 0;
	private PrintStream _info;

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

	private void setNonceLength(int value) {
		_nonceLength = value;
	}

	private boolean hasTagLength() {
		return _tagLength != 0; 
	}

	private void setTagLength(int value) {
		if (AES_GCM_TAG_LENGTH_MIN <= value && value <= AES_GCM_TAG_LENGTH_MAX) {
			_tagLength = value;
		} else {
			throw new RuntimeException("Tag length is out of range.");
		}
	}

	private boolean hasKey() {
		return _key != null;
	}

	private boolean hasIv() {
		return _iv != null;
	}

	private boolean hasNonce() {
		return _nonce != null;
	}

	private void setKey(String value) {
		_key = HexString.parse(value);
	}

	private void setIv(String value) {
		_iv = HexString.parse(value);
	}

	private void setNonce(String value) {
		_nonce = HexString.parse(value);
	}

	private void setKeyPhrase(String value) {
		_key = generate32Bytes(value);
	}

	private void setIvPhrase(String value) {
		_iv = generate32Bytes(value);
	}

	private void setNoncePhrase(String value) {
		_nonce = generate32Bytes(value);
	}

	private static byte[] generate32Bytes(String value) {
		try {
			MessageDigest md = MessageDigest.getInstance(SHA_256);
			return md.digest(value.getBytes());
		} catch (Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}

	private boolean hasAad() {
		return _aad != null;
	}

	private void setAad(String value) {
		_aad = HexString.parse(value);
	}

	private void setAadText(String value) {
		_aad = value.getBytes();
	}

	private void setInputPath(int operation, String fileName) {
		_operation = operation;
		_inFileName = fileName;
	}

	private void setOutputPath(String fileName) {
		_outFileName = fileName;
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
		verifyNonce();
		verifyAad();
		InputStream in = null;
		OutputStream out = null;
		try {
			in = openInput();
			out = openOutput();
			Cipher cipher = getCipher();
			if (_aad != null) {
				cipher.updateAAD(_aad);
			}
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
			_info.printf("%s in\n", TextHelpers.numberOfBytes(inBytes));
			byte[] result = cipher.doFinal();
			if (result != null) {
				out.write(result);
				outBytes += result.length;
			}
			out.flush();
			_info.printf("%s out\n", TextHelpers.numberOfBytes(outBytes));
		} finally {
			closeOutput(out);
			closeInput(in);
		}
	}

	private void verifyParameters() {
		if (_transformation == null) {
			throw new RuntimeException("Algorithm is not specified.");
		}
		if (_operation == 0) {
			throw new RuntimeException("Mode(encrypt/decrypt) is not specified.");
		}
		if (_outFileName == null) {
			throw new RuntimeException("Output file is not specified.");
		}
	}

	private void verifyKey() throws Exception {
		if (hasKey()) {
			_key = adjustLength(_key, _keyLength);
		} else {
			throw new RuntimeException("Private key is not specified.");
		}
	}

	private void verifyIv() throws Exception {
		if (_ivLength > 0) {
			if (hasIv()) {
				_iv = adjustLength(_iv, _ivLength);
			} else {
				throw new RuntimeException("Initial vector is not specified.");
			}
		} else if (hasIv()) {
			throw new RuntimeException("Initial vector is not required.");
		}
	}

	private void verifyNonce() throws Exception {
		if (_nonceLength > 0) {
			if (hasNonce()) {
				_nonce = adjustLength(_nonce, _nonceLength);
			} else {
				_nonce = adjustLength(generate32Bytes(String.format("%d", System.currentTimeMillis())), _nonceLength);
			}
		} else if (hasNonce()) {
			throw new RuntimeException("Nonce is not required.");
		}
	}

	private static byte[] adjustLength(byte[] value, int length) {
		if (value.length != length) {
			return Arrays.copyOf(value, length);
		} else {
			return value;
		}
	}

	private void verifyAad() {
		if (mode().equals("GCM")) {
			// OK
		} else if (hasAad()) {
			throw new RuntimeException("Additional authentication data cannot be specified.");
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
			_info = System.err;
		} else {
			Path path = Paths.get(_outFileName);
			if (!canOverwrite() && Files.exists(path)) {
				throw new RuntimeException("Output file already exists.");
			}
			out = Files.newOutputStream(path);
			setFlags(FLAG_OUT_TO_CLOSE | FLAG_INFO_TO_PRINT);
			_info = System.out;
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
		String mode = this.mode();
		if (mode.equals("CBC") || mode.equals("CFB") || mode.equals("OFB")) {
			SecretKeySpec keySpec = new SecretKeySpec(_key, algorithm());
			IvParameterSpec ivSpec = new IvParameterSpec(_iv);
			cipher.init(_operation, keySpec, ivSpec);
			_info.printf("KEY %s\n", HexString.toString(_key));
			_info.printf(" IV %s\n", HexString.toString(_iv));
		} else if (mode.equals("GCM")) {
			if (_tagLength == 0) {
				_tagLength = AES_GCM_TAG_LENGTH_MIN;
			}
			SecretKeySpec keySpec = new SecretKeySpec(_key, algorithm());
			GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(_tagLength * 8, _nonce);
			cipher.init(_operation, keySpec, gcmParameterSpec);
			_info.printf("  KEY %s\n", HexString.toString(_key));
			_info.printf("NONCE %s\n", HexString.toString(_nonce));
			if (_aad != null) {
				_info.printf("  AAD %s\n", HexString.toString(_aad));
			}
		} else {
			SecretKeySpec keySpec = new SecretKeySpec(_key, algorithm());
			cipher.init(_operation, keySpec);
			_info.printf("KEY %s\n", HexString.toString(_key));
		}
		return cipher;
	}

	private String algorithm() {
		return _transformation.split("/")[0];
	}

	private String mode() {
		return _transformation.split("/")[1].substring(0, 3);
	}

	public CommandLineParameters commandLineParameters() {
		return (new CommandLineParameters())
				.add("aes-256-cbc", transformationDescription(AES_CBC_PKCS5PADDING, 256), (p) -> {
					setTransformation(AES_CBC_PKCS5PADDING);
					setKeyLength(AES_256_KEY_LENGTH);
					setIvLength(AES_IV_LENGTH);
					return true;
				})
				.add("aes-192-cbc", transformationDescription(AES_CBC_PKCS5PADDING, 192), (p) -> {
					setTransformation(AES_CBC_PKCS5PADDING);
					setKeyLength(AES_192_KEY_LENGTH);
					setIvLength(AES_IV_LENGTH);
					return true;
				})
				.add("aes-128-cbc", transformationDescription(AES_CBC_PKCS5PADDING, 128), (p) -> {
					setTransformation(AES_CBC_PKCS5PADDING);
					setKeyLength(AES_128_KEY_LENGTH);
					setIvLength(AES_IV_LENGTH);
					return true;
				})
				.add("aes-256-ecb", transformationDescription(AES_ECB_PKCS5PADDING, 256), (p) -> {
					setTransformation(AES_ECB_PKCS5PADDING);
					setKeyLength(AES_256_KEY_LENGTH);
					return true;
				})
				.add("aes-192-ecb", transformationDescription(AES_ECB_PKCS5PADDING, 192), (p) -> {
					setTransformation(AES_ECB_PKCS5PADDING);
					setKeyLength(AES_192_KEY_LENGTH);
					return true;
				})
				.add("aes-128-ecb", transformationDescription(AES_ECB_PKCS5PADDING, 128), (p) -> {
					setTransformation(AES_ECB_PKCS5PADDING);
					setKeyLength(AES_128_KEY_LENGTH);
					return true;
				})
				.add("aes-256-cfb", transformationDescription(AES_CFB8_NOPADDING, 256), (p) -> {
					setTransformation(AES_CFB8_NOPADDING);
					setKeyLength(AES_256_KEY_LENGTH);
					setIvLength(AES_IV_LENGTH);
					return true;
				})
				.add("aes-192-cfb", transformationDescription(AES_CFB8_NOPADDING, 192), (p) -> {
					setTransformation(AES_CFB8_NOPADDING);
					setKeyLength(AES_192_KEY_LENGTH);
					setIvLength(AES_IV_LENGTH);
					return true;
				})
				.add("aes-128-cfb", transformationDescription(AES_CFB8_NOPADDING, 128), (p) -> {
					setTransformation(AES_CFB8_NOPADDING);
					setKeyLength(AES_128_KEY_LENGTH);
					setIvLength(AES_IV_LENGTH);
					return true;
				})
				.add("aes-256-ofb", transformationDescription(AES_OFB8_NOPADDING, 256), (p) -> {
					setTransformation(AES_OFB8_NOPADDING);
					setKeyLength(AES_256_KEY_LENGTH);
					setIvLength(AES_IV_LENGTH);
					return true;
				})
				.add("aes-192-ofb", transformationDescription(AES_OFB8_NOPADDING, 192), (p) -> {
					setTransformation(AES_OFB8_NOPADDING);
					setKeyLength(AES_192_KEY_LENGTH);
					setIvLength(AES_IV_LENGTH);
					return true;
				})
				.add("aes-128-ofb", transformationDescription(AES_OFB8_NOPADDING, 128), (p) -> {
					setTransformation(AES_OFB8_NOPADDING);
					setKeyLength(AES_128_KEY_LENGTH);
					setIvLength(AES_IV_LENGTH);
					return true;
				})
				.add("aes-256-gcm", transformationDescription(AES_GCM_NOPADDING, 256), (p) -> {
					setTransformation(AES_GCM_NOPADDING);
					setKeyLength(AES_256_KEY_LENGTH);
					setNonceLength(AES_GCM_NONCE_LENGTH);
					return true;
				})
				.add("aes-192-gcm", transformationDescription(AES_GCM_NOPADDING, 192), (p) -> {
					setTransformation(AES_GCM_NOPADDING);
					setKeyLength(AES_192_KEY_LENGTH);
					setNonceLength(AES_GCM_NONCE_LENGTH);
					return true;
				})
				.add("aes-128-gcm", transformationDescription(AES_GCM_NOPADDING, 128), (p) -> {
					setTransformation(AES_GCM_NOPADDING);
					setKeyLength(AES_128_KEY_LENGTH);
					setNonceLength(AES_GCM_NONCE_LENGTH);
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
						if (!hasKey()) {
							setKey(p.argument());
							return true;
						} else {
							throw new RuntimeException("Private key is already specified.");
						}
					} else {
						throw new RuntimeException("Private key is not specified.");
					}
				})
				.add("-iv", "HEXSTRING", "specifies initial vector", (p) -> {
					if (p.next()) {
						if (!hasIv()) {
							setIv(p.argument());
							return true;
						} else {
							throw new RuntimeException("Initial vector is already specified.");
						}
					} else {
						throw new RuntimeException("Initial vector is not specified.");
					}
				})
				.add("-nonce", "HEXSTRING", "specifies nonce", (p) -> {
					if (p.next()) {
						if (!hasNonce()) {
							setNonce(p.argument());
							return true;
						} else {
							throw new RuntimeException("Nonce is already specified.");
						}
					} else {
						throw new RuntimeException("Nonce is not specified.");
					}
				})
				.add("-keyphrase", "TEXT", "specifies text phrase to generate private key", (p) -> {
					if (p.next()) {
						if (!hasKey()) {
							setKeyPhrase(p.argument());
							return true;
						} else {
							throw new RuntimeException("Private key is already specified.");
						}
					} else {
						throw new RuntimeException("Key phrase is not specified.");
					}
				})
				.add("-ivphrase", "TEXT", "specifies text phrase to generate initial vector", (p) -> {
					if (p.next()) {
						if (!hasIv()) {
							setIvPhrase(p.argument());
							return true;
						} else {
							throw new RuntimeException("Initial vector is already specified.");
						}
					} else {
						throw new RuntimeException("IV phrase is not specified.");
					}
				})
				.add("-noncephrase", "TEXT", "specifies text phrase to generate nonce", (p) -> {
					if (p.next()) {
						if (!hasNonce()) {
							setNoncePhrase(p.argument());
							return true;
						} else {
							throw new RuntimeException("Nonce is already specified.");
						}
					} else {
						throw new RuntimeException("Nonce phrase is not specified.");
					}
				})
				.add("-tag", "NUMBER", String.format("specifies tag length (min=%d max=%d)", AES_GCM_TAG_LENGTH_MIN, AES_GCM_TAG_LENGTH_MAX), (p) -> {
					if (p.next()) {
						if (!hasTagLength()) {
							setTagLength(p.intArgument());
						} else {
							throw new RuntimeException("Tag length is already specified.");
						}
						return true;
					} else {
						throw new RuntimeException("Tag length is not specified.");
					}
				})
				.add("-aadata", "HEXSTRING", "specifies additional authentication data", (p) -> {
					if (p.next()) {
						if (!hasAad()) {
							setAad(p.argument());
							return true;
						} else {
							throw new RuntimeException("Additional authentication data is already specified.");
						}
					} else {
						throw new RuntimeException("Additional authentication data value is not specified.");
					}
				})
				.add("-aatext", "TEXT", "specifies additional authentication text", (p) -> {
					if (p.next()) {
						if (!hasAad()) {
							setAadText(p.argument());
							return true;
						} else {
							throw new RuntimeException("Additional authentication data is already specified.");
						}
					} else {
						throw new RuntimeException("Additional authentication text is not specified.");
					}
				})
				.add("-overwrite", "writes to output file even if it already exists", (p) -> {
					setFlags(FLAG_OVERWRITE);
					return true;
				})
				.add("-help", "prints this message", (p) -> {
					help(p);
					return false;
				})
				.addAlias("-e", "-encrypt")
				.addAlias("-d", "-decrypt")
				.addAlias("-o", "-out")
				.addAlias("-k", "-key")
				.addAlias("-i", "-iv")
				.addAlias("-n", "-nonce")
				.addAlias("-a", "-aadata")
				.addAlias("-K", "-keyphrase")
				.addAlias("-I", "-ivphrase")
				.addAlias("-N", "-noncephrase")
				.addAlias("-A", "-aatext")
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
			if (args.length == 0) {
				help(parameters);
			} else if (parameters.process(args)) {
				app.run();
			}
			System.exit(0);
		} catch (Throwable t) {
			printError(t);
			System.exit(1);
		}
	}

	private static void help(CommandLineParameters parameters) {
		System.out.printf(DESCRIPTION, VERSION);
		System.out.printf("%s", parameters);
	}

	private static void printError(Throwable t) {
		System.err.printf("ERROR: %s\n", t.getMessage());
		while ((t = t.getCause()) != null) {
			System.err.printf("       %s\n", t.getMessage());
		}
	}

}
