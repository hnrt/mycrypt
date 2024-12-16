package com.hideakin.mycrypto;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.hideakin.mycrypto.constant.Algorithm;
import com.hideakin.mycrypto.constant.OperationalMode;
import com.hideakin.mycrypto.constant.Padding;
import com.hideakin.util.CommandLineParameters;
import com.hideakin.util.HexString;
import com.hideakin.util.TextHelpers;

public class MyCryptographyUtilityApplication {

	public static final String VERSION = "0.7.0";

	public static final String DESCRIPTION = "My Cryptography Utility version %s\n";

	private static final int AES_256_KEY_LENGTH = 256 / 8;
	private static final int AES_192_KEY_LENGTH = 192 / 8;
	private static final int AES_128_KEY_LENGTH = 128 / 8;
	private static final int AES_IV_LENGTH = 16;
	private static final int AES_GCM_NONCE_LENGTH = 12;
	private static final int AES_GCM_TAG_LENGTH_MIN = 12;
	private static final int AES_GCM_TAG_LENGTH_MAX = 16;
	
	private static final int FLAG_OVERWRITE = 1 << 0;
	private static final int FLAG_IN_TO_CLOSE = 1 << 1;
	private static final int FLAG_OUT_TO_CLOSE = 1 << 2;

	private Algorithm _algorithm = Algorithm.UNDEFINED;
	private OperationalMode _mode = OperationalMode.UNDEFINED;
	private Padding _padding = Padding.UNDEFINED;
	private int _keyLength = 0;
	private int _ivLength = 0;
	private int _nonceLength = 0;
	private int _tagLength = 0;
	private byte[] _key;
	private byte[] _iv;
	private byte[] _nonce;
	private byte[] _aad; // Additional Authenticated Data
	private String _inFileName;
	private String _outFileName;
	private Path _outPath;
	private Path _tmpPath;
	private int _operation = 0;
	private int _flags = 0;
	private PrintStream _info;
	@SuppressWarnings("serial")
	private final Map<OperationalMode, Supplier<Cipher>> _cipherSupplier = new HashMap<OperationalMode, Supplier<Cipher>>() {
		{
			put(OperationalMode.CBC, () -> { return getCipherWithKeyAndIv(); });
			put(OperationalMode.ECB, () -> { return getCipherWithKey(); });
			put(OperationalMode.CFB8, () -> { return getCipherWithKeyAndIv(); });
			put(OperationalMode.OFB8, () -> { return getCipherWithKeyAndIv(); });
			put(OperationalMode.GCM, () -> { return getCipherWithGcmParameterSpec(); });
		}
	};

	public MyCryptographyUtilityApplication() {
	}

	private void setTransformation(Algorithm algorithm, OperationalMode mode, Padding padding, int keyLength) {
		if (_algorithm != Algorithm.UNDEFINED) {
			throw new RuntimeException("Algorithm is specified more than once.");
		}
		_algorithm = algorithm;
		_mode = mode;
		_padding = padding;
		_keyLength = keyLength;
		if (mode == OperationalMode.CBC || mode == OperationalMode.CFB8 || mode == OperationalMode.OFB8) {
			_ivLength = AES_IV_LENGTH;
		} else if (mode == OperationalMode.GCM) {
			_nonceLength = AES_GCM_NONCE_LENGTH;
		}
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

	private void setKey(byte[] value) {
		_key = value;
	}

	private void setIv(byte[] value) {
		_iv = value;
	}

	private void setNonce(byte[] value) {
		_nonce = value;
	}

	private boolean hasAad() {
		return _aad != null;
	}

	private void setAad(byte[] value) {
		_aad = value;
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
	
	private void resetFlags(int value) {
		_flags &= ~value;
	}

	private boolean checkFlags(int value) {
		return (_flags & value) == value;
	}

	public void run() throws Exception {
		verifyParameters();
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
			_info.printf("%s in\n", TextHelpers.numberOfBytes(inBytes));
			closeInput(in);
			byte[] result = cipher.doFinal();
			if (result != null) {
				out.write(result);
				outBytes += result.length;
			}
			out.flush();
			_info.printf("%s out\n", TextHelpers.numberOfBytes(outBytes));
			commitOutput(out);
		} finally {
			closeInput(in);
			closeOutput(out);
		}
	}

	private void verifyParameters() throws Exception {
		if (_algorithm == Algorithm.UNDEFINED) {
			throw new RuntimeException("Algorithm is not specified.");
		}
		if (_operation == 0) {
			throw new RuntimeException("Operation(encrypt/decrypt) is not specified.");
		}
		if (_outFileName == null) {
			throw new RuntimeException("Output file is not specified.");
		}
		verifyKey();
		verifyIv();
		verifyNonce();
		verifyAad();
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
				_iv = adjustLength(generate32Bytes(null), _ivLength);
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
				_nonce = adjustLength(generate32Bytes(null), _nonceLength);
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
		if (_mode == OperationalMode.GCM) {
			// OK
		} else if (hasAad()) {
			throw new RuntimeException(String.format("Additional authentication data cannot be specified for %s.", _mode.label()));
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
	
	private void closeInput(InputStream in) {
		if (checkFlags(FLAG_IN_TO_CLOSE)) {
			try {
				in.close();
				resetFlags(FLAG_IN_TO_CLOSE);
			} catch (Exception e) {
				printError(e);
			}
		}
	}

	private OutputStream openOutput() throws Exception {
		OutputStream out;
		if ("-".equals(_outFileName)) {
			out = System.out;
			_info = System.err;
		} else {
			_outPath = Paths.get(_outFileName);
			if (!checkFlags(FLAG_OVERWRITE)&& Files.exists(_outPath)) {
				throw new RuntimeException("Output file already exists.");
			}
			_tmpPath = Paths.get(String.format("%s.%d", _outFileName, System.currentTimeMillis()));
			out = Files.newOutputStream(_tmpPath);
			setFlags(FLAG_OUT_TO_CLOSE);
			_info = System.out;
		}
		return out;
	}
	
	private void commitOutput(OutputStream out) throws Exception {
		if (checkFlags(FLAG_OUT_TO_CLOSE)) {
			out.close();
			resetFlags(FLAG_OUT_TO_CLOSE);
			if (checkFlags(FLAG_OVERWRITE)) {
				Files.move(_tmpPath, _outPath, StandardCopyOption.REPLACE_EXISTING);
			} else if (Files.exists(_outPath)) {
				throw new RuntimeException("Output file already exists.");
			} else {
				Files.move(_tmpPath, _outPath);
			}
		}
	}

	private void closeOutput(OutputStream out) {
		if (checkFlags(FLAG_OUT_TO_CLOSE)) {
			try {
				out.close();
				resetFlags(FLAG_OUT_TO_CLOSE);
			} catch (Exception e) {
				printError(e);
			}
		}
	}

	private Cipher getCipher() throws Exception {
		return _cipherSupplier.get(_mode).get();
	}

	private Cipher getCipherWithKeyAndIv() {
		try {
			SecretKeySpec keySpec = new SecretKeySpec(_key, _algorithm.label());
			IvParameterSpec ivSpec = new IvParameterSpec(_iv);
			Cipher cipher = Cipher.getInstance(transformation());
			cipher.init(_operation, keySpec, ivSpec);
			_info.printf("KEY %s\n", HexString.toString(_key));
			_info.printf(" IV %s\n", HexString.toString(_iv));
			return cipher;
		} catch (Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}

	private Cipher getCipherWithKey() {
		try {
			SecretKeySpec keySpec = new SecretKeySpec(_key, _algorithm.label());
			Cipher cipher = Cipher.getInstance(transformation());
			cipher.init(_operation, keySpec);
			_info.printf("KEY %s\n", HexString.toString(_key));
			return cipher;
		} catch (Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}

	private Cipher getCipherWithGcmParameterSpec() {
		try {
			if (_tagLength == 0) {
				_tagLength = AES_GCM_TAG_LENGTH_MIN;
			}
			SecretKeySpec keySpec = new SecretKeySpec(_key, _algorithm.label());
			GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(_tagLength * 8, _nonce);
			Cipher cipher = Cipher.getInstance(transformation());
			cipher.init(_operation, keySpec, gcmParameterSpec);
			_info.printf("  KEY %s\n", HexString.toString(_key));
			_info.printf("NONCE %s\n", HexString.toString(_nonce));
			_info.printf("  TAG %d\n", _tagLength);
			if (_aad != null) {
				cipher.updateAAD(_aad);
				_info.printf("  AAD %s\n", HexString.toString(_aad));
			}
			return cipher;
		} catch (Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}

	private String transformation() {
		return String.format("%s/%s/%s", _algorithm.label(), _mode.label(), _padding.label());
	}

	private static final String SHA_256 = "SHA-256";

	private static byte[] generate32Bytes(String value) {
		try {
			if (value == null) {
				value = String.format("%d", System.nanoTime());
			}
			MessageDigest md = MessageDigest.getInstance(SHA_256);
			return md.digest(value.getBytes());
		} catch (Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}

	public CommandLineParameters commandLineParameters() {
		return (new CommandLineParameters())
				.add("aes-256-cbc", transformationDescription(Algorithm.AES, OperationalMode.CBC, Padding.PKCS5, 256), (p) -> {
					setTransformation(Algorithm.AES, OperationalMode.CBC, Padding.PKCS5, AES_256_KEY_LENGTH);
					return true;
				})
				.add("aes-192-cbc", transformationDescription(Algorithm.AES, OperationalMode.CBC, Padding.PKCS5, 192), (p) -> {
					setTransformation(Algorithm.AES, OperationalMode.CBC, Padding.PKCS5, AES_192_KEY_LENGTH);
					return true;
				})
				.add("aes-128-cbc", transformationDescription(Algorithm.AES, OperationalMode.CBC, Padding.PKCS5, 128), (p) -> {
					setTransformation(Algorithm.AES, OperationalMode.CBC, Padding.PKCS5, AES_128_KEY_LENGTH);
					return true;
				})
				.add("aes-256-ecb", transformationDescription(Algorithm.AES, OperationalMode.ECB, Padding.PKCS5, 256), (p) -> {
					setTransformation(Algorithm.AES, OperationalMode.ECB, Padding.PKCS5, AES_256_KEY_LENGTH);
					return true;
				})
				.add("aes-192-ecb", transformationDescription(Algorithm.AES, OperationalMode.ECB, Padding.PKCS5, 192), (p) -> {
					setTransformation(Algorithm.AES, OperationalMode.ECB, Padding.PKCS5, AES_192_KEY_LENGTH);
					return true;
				})
				.add("aes-128-ecb", transformationDescription(Algorithm.AES, OperationalMode.ECB, Padding.PKCS5, 128), (p) -> {
					setTransformation(Algorithm.AES, OperationalMode.ECB, Padding.PKCS5, AES_128_KEY_LENGTH);
					return true;
				})
				.add("aes-256-cfb", transformationDescription(Algorithm.AES, OperationalMode.CFB8, Padding.NONE, 256), (p) -> {
					setTransformation(Algorithm.AES, OperationalMode.CFB8, Padding.NONE, AES_256_KEY_LENGTH);
					return true;
				})
				.add("aes-192-cfb", transformationDescription(Algorithm.AES, OperationalMode.CFB8, Padding.NONE, 192), (p) -> {
					setTransformation(Algorithm.AES, OperationalMode.CFB8, Padding.NONE, AES_192_KEY_LENGTH);
					return true;
				})
				.add("aes-128-cfb", transformationDescription(Algorithm.AES, OperationalMode.CFB8, Padding.NONE, 128), (p) -> {
					setTransformation(Algorithm.AES, OperationalMode.CFB8, Padding.NONE, AES_128_KEY_LENGTH);
					return true;
				})
				.add("aes-256-ofb", transformationDescription(Algorithm.AES, OperationalMode.OFB8, Padding.NONE, 256), (p) -> {
					setTransformation(Algorithm.AES, OperationalMode.OFB8, Padding.NONE, AES_256_KEY_LENGTH);
					return true;
				})
				.add("aes-192-ofb", transformationDescription(Algorithm.AES, OperationalMode.OFB8, Padding.NONE, 192), (p) -> {
					setTransformation(Algorithm.AES, OperationalMode.OFB8, Padding.NONE, AES_192_KEY_LENGTH);
					return true;
				})
				.add("aes-128-ofb", transformationDescription(Algorithm.AES, OperationalMode.OFB8, Padding.NONE, 128), (p) -> {
					setTransformation(Algorithm.AES, OperationalMode.OFB8, Padding.NONE, AES_128_KEY_LENGTH);
					return true;
				})
				.add("aes-256-gcm", transformationDescription(Algorithm.AES, OperationalMode.GCM, Padding.NONE, 256), (p) -> {
					setTransformation(Algorithm.AES, OperationalMode.GCM, Padding.NONE, AES_256_KEY_LENGTH);
					return true;
				})
				.add("aes-192-gcm", transformationDescription(Algorithm.AES, OperationalMode.GCM, Padding.NONE, 192), (p) -> {
					setTransformation(Algorithm.AES, OperationalMode.GCM, Padding.NONE, AES_192_KEY_LENGTH);
					return true;
				})
				.add("aes-128-gcm", transformationDescription(Algorithm.AES, OperationalMode.GCM, Padding.NONE, 128), (p) -> {
					setTransformation(Algorithm.AES, OperationalMode.GCM, Padding.NONE, AES_128_KEY_LENGTH);
					return true;
				})
				.add("-encrypt", "PATH", "specifies input file to encrypt\nreads from standard input if a hyphen is specified", (p) -> {
					if (p.next()) {
						setInputPath(Cipher.ENCRYPT_MODE, p.argument());
						return true;
					} else {
						throw new RuntimeException("Input file is not specified.");
					}
				})
				.add("-decrypt", "PATH", "specifies input file to decrypt\nreads from standard input if a hyphen is specified", (p) -> {
					if (p.next()) {
						setInputPath(Cipher.DECRYPT_MODE, p.argument());
						return true;
					} else {
						throw new RuntimeException("Input file is not specified.");
					}
				})
				.add("-out", "PATH", "specifies output file\nwrites to standard output if a hyphen is specified", (p) -> {
					if (p.next()) {
						setOutputPath(p.argument());
						return true;
					} else {
						throw new RuntimeException("Output file is not specified.");
					}
				})
				.add("-overwrite", "PATH", "specifies output file\nwrites to file even if it exists", (p) -> {
					if (p.next()) {
						setOutputPath(p.argument());
						setFlags(FLAG_OVERWRITE);
						return true;
					} else {
						throw new RuntimeException("Output file is not specified.");
					}
				})
				.add("-key", "HEXSTRING", "specifies private key", (p) -> {
					if (p.next()) {
						if (!hasKey()) {
							setKey(p.binaryArgument());
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
							setIv(p.binaryArgument());
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
							setNonce(p.binaryArgument());
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
							setKey(generate32Bytes(p.argument()));
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
							setIv(generate32Bytes(p.argument()));
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
							setNonce(generate32Bytes(p.argument()));
							return true;
						} else {
							throw new RuntimeException("Nonce is already specified.");
						}
					} else {
						throw new RuntimeException("Nonce phrase is not specified.");
					}
				})
				.add("-tag", "NUMBER", String.format("specifies tag length\nGCM: min=%d max=%d", AES_GCM_TAG_LENGTH_MIN, AES_GCM_TAG_LENGTH_MAX), (p) -> {
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
							setAad(p.binaryArgument());
							return true;
						} else {
							throw new RuntimeException("Additional authentication data is already specified.");
						}
					} else {
						throw new RuntimeException("Additional authentication data value is not specified.");
					}
				})
				.add("-aatext", "TEXT", "specifies additional authentication data with text", (p) -> {
					if (p.next()) {
						if (!hasAad()) {
							setAad(p.argument().getBytes());
							return true;
						} else {
							throw new RuntimeException("Additional authentication data is already specified.");
						}
					} else {
						throw new RuntimeException("Additional authentication data is not specified with text.");
					}
				})
				.add("-help", "prints this message", (p) -> {
					help(p);
					return false;
				})
				.addAlias("-e", "-encrypt")
				.addAlias("-d", "-decrypt")
				.addAlias("-o", "-out")
				.addAlias("-O", "-overwrite")
				.addAlias("-k", "-key")
				.addAlias("-i", "-iv")
				.addAlias("-n", "-nonce")
				.addAlias("-t", "-tag")
				.addAlias("-a", "-aadata")
				.addAlias("-K", "-keyphrase")
				.addAlias("-I", "-ivphrase")
				.addAlias("-N", "-noncephrase")
				.addAlias("-A", "-aatext")
				.addAlias("-h", "-help");
	}

	private static String transformationDescription(Algorithm algorithm, OperationalMode mode, Padding padding, int keyBits) {
		return String.format("%s [%s] padding=%s key=%d-bits", algorithm.label(), mode.description(), padding.description(), keyBits);
	}

	private void cleanup() {
		if (_tmpPath != null) {
			try {
				if (Files.exists(_tmpPath)) {
					Files.delete(_tmpPath);
				}
			} catch (Exception e) {
				printError(e);
			}
		}
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
		} finally {
			app.cleanup();
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
