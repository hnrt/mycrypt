package com.hideakin.mycrypt;

import static org.junit.Assert.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.Before;
import org.junit.Test;

public class MyCryptographyUtilityTest {

	private static final String DATA1 = "0123456789ABCDEF";
	private static final String DATA2 = "0123456789ABCDEFG";
	private static final String DATA3 = "月が手前を通過することによって土星が隠れる天文現象「土星食」が8日夜、観測された。";
	private static final String DATA4 = "今季Ｊ１初挑戦で３位と躍進した町田からは選出ゼロとなった。";

	private static final String TMPDIR = Paths.get(System.getProperty("java.io.tmpdir"), "MyCryptographyUtilityTest").toString();

	@Before
	public void setUp() throws Exception {
		Path path = Paths.get(TMPDIR);
		if (Files.exists(path)) {
			Files.list(path).forEach((p) -> {
				try {
					System.out.printf("deleting %s\n", p);
					Files.delete(p);
				} catch (Exception e) {
					System.out.printf("ERROR: %s\n", e.getMessage());
				}
			});
		} else {
			Files.createDirectory(path);
		}
	}

	@Test
	public void test_cbc_1_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cbc_1_1.in");
		Path outPath = Paths.get(TMPDIR, "test_cbc_1_1.out");
		byte[] inData = DATA1.getBytes();
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-cbc",
				"-e", inPath.toString(),
				"-o", outPath.toString(),
				"-K", "xyzzy",
				"-I", "20241210"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("C3578853E13E75D944113C4637BFD5FAB074A85601DA8F835017C0E247103DE9", actual);
	}

	@Test
	public void test_cbc_1_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cbc_1_2.in");
		Path outPath = Paths.get(TMPDIR, "test_cbc_1_2.out");
		byte[] inData = HexString.parse("C3578853E13E75D944113C4637BFD5FAB074A85601DA8F835017C0E247103DE9");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-cbc",
				"-d", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED622F5EE078671AED",
				"-i", "B87E2F0E1BEB474894C501960ECBE847"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		assertEquals(16, result.length);
		String actual = new String(result);
		System.out.printf("#%s\n", actual);
		assertEquals(DATA1, actual);
	}

	@Test
	public void test_cbc_2_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cbc_2_1.in");
		Path outPath = Paths.get(TMPDIR, "test_cbc_2_1.out");
		byte[] inData = DATA2.getBytes();
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-cbc",
				"-e", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED622F5EE078671AED",
				"-i", "B87E2F0E1BEB474894C501960ECBE847"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("C3578853E13E75D944113C4637BFD5FA31534153CB71E59ECF786D3F0A4814D1", actual);
	}

	@Test
	public void test_cbc_2_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cbc_2_2.in");
		Path outPath = Paths.get(TMPDIR, "test_cbc_2_2.out");
		byte[] inData = HexString.parse("C3578853E13E75D944113C4637BFD5FA31534153CB71E59ECF786D3F0A4814D1");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-cbc",
				"-d", inPath.toString(),
				"-o", outPath.toString(),
				"-K", "xyzzy",
				"-I", "20241210"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		assertEquals(17, result.length);
		String actual = new String(result);
		System.out.printf("#%s\n", actual);
		assertEquals(DATA2, actual);
	}

	@Test
	public void test_cbc_3_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cbc_3_1.in");
		Path outPath = Paths.get(TMPDIR, "test_cbc_3_1.out");
		byte[] inData = DATA3.getBytes();
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-192-cbc",
				"-e", inPath.toString(),
				"-o", outPath.toString(),
				"-K", "xyzzy",
				"-I", "20241210"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("9CAAF4293A8CFCC65FAC205399164F79C04F6CBB0E12E79AF3F9EAEC554EFB137625947FB64530C05D84B494D07F0C55D9E6156B6EE5AC2D95AE84BD90BF0ED49DF11A4CBB77276AC6D4C430C6BC52244BA5B5ADD959B9B0D89D363AE4CE0C61E3B1D89500A3E5E3123A8BA4E750428D5D2FE680DB8336394917F2CCEA1B7B9D", actual);
	}

	@Test
	public void test_cbc_3_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cbc_3_2.in");
		Path outPath = Paths.get(TMPDIR, "test_cbc_3_2.out");
		byte[] inData = HexString.parse("9CAAF4293A8CFCC65FAC205399164F79C04F6CBB0E12E79AF3F9EAEC554EFB137625947FB64530C05D84B494D07F0C55D9E6156B6EE5AC2D95AE84BD90BF0ED49DF11A4CBB77276AC6D4C430C6BC52244BA5B5ADD959B9B0D89D363AE4CE0C61E3B1D89500A3E5E3123A8BA4E750428D5D2FE680DB8336394917F2CCEA1B7B9D");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-192-cbc",
				"-d", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED",
				"-i", "B87E2F0E1BEB474894C501960ECBE847"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = new String(result);
		System.out.printf("#%s\n", actual);
		assertEquals(DATA3, actual);
	}

	@Test
	public void test_cbc_4_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cbc_4_1.in");
		Path outPath = Paths.get(TMPDIR, "test_cbc_4_1.out");
		byte[] inData = DATA4.getBytes();
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-128-cbc",
				"-e", inPath.toString(),
				"-o", outPath.toString(),
				"-K", "xyzzy",
				"-I", "20241210"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("766A42A99FD13987CA0D315EBCABB00F3DE7D2383FD88860360DFDD1BC13A5D620B26C7396F0FAA3AAD542C1BA404387C5990CAEBBC18DE3F7BCCA5E0E11B618A0A7B84B1BA1C8B947641B53E45D63F3362195206F9A8C641F1549E3C7FA2EEC", actual);
	}

	@Test
	public void test_cbc_4_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cbc_4_2.in");
		Path outPath = Paths.get(TMPDIR, "test_cbc_4_2.out");
		byte[] inData = HexString.parse("766A42A99FD13987CA0D315EBCABB00F3DE7D2383FD88860360DFDD1BC13A5D620B26C7396F0FAA3AAD542C1BA404387C5990CAEBBC18DE3F7BCCA5E0E11B618A0A7B84B1BA1C8B947641B53E45D63F3362195206F9A8C641F1549E3C7FA2EEC");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-128-cbc",
				"-d", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE",
				"-i", "B87E2F0E1BEB474894C501960ECBE847"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = new String(result);
		System.out.printf("#%s\n", actual);
		assertEquals(DATA4, actual);
	}

	@Test
	public void test_cbc_5_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cbc_5_1.in");
		Path outPath = Paths.get(TMPDIR, "test_cbc_5_1.out");
		byte[] inData = DATA3.getBytes();
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-cbc",
				"-e", inPath.toString(),
				"-o", outPath.toString(),
				"-K", "xyzzy",
				"-I", "20241210"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("7B71A870DAB0C286DB0FD6F5A6CB6DA67FB1AAF50B1E552204ED46EDF2B434619EF512C5F74BBA4ABBBD76D540D97642CC7AFC5DF121322D7946488982A83E98BEEBB22A759F89C7DAAADFC8E7D1A0104540393CD97D5B39167B3C3C0BAFC1BCA0A69384F2ECC08237A71E34D6A77A0A191300ADA83E3504A96EACE0939169B8", actual);
	}

	@Test
	public void test_cbc_5_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cbc_5_2.in");
		Path outPath = Paths.get(TMPDIR, "test_cbc_5_2.out");
		byte[] inData = HexString.parse("7B71A870DAB0C286DB0FD6F5A6CB6DA67FB1AAF50B1E552204ED46EDF2B434619EF512C5F74BBA4ABBBD76D540D97642CC7AFC5DF121322D7946488982A83E98BEEBB22A759F89C7DAAADFC8E7D1A0104540393CD97D5B39167B3C3C0BAFC1BCA0A69384F2ECC08237A71E34D6A77A0A191300ADA83E3504A96EACE0939169B8");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-cbc",
				"-d", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED622F5EE078671AED",
				"-i", "B87E2F0E1BEB474894C501960ECBE847"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = new String(result);
		System.out.printf("#%s\n", actual);
		assertEquals(DATA3, actual);
	}

	@Test
	public void test_ecb_1_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ecb_1_1.in");
		Path outPath = Paths.get(TMPDIR, "test_ecb_1_1.out");
		byte[] inData = DATA1.getBytes();
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-ecb",
				"-e", inPath.toString(),
				"-o", outPath.toString(),
				"-K", "xyzzy"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("DAD0BC105BCD60F44B5E86DF21C86E7E85F7AD59268F6C527045AF291ABBB2D0", actual);
	}

	@Test
	public void test_ecb_1_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ecb_1_2.in");
		Path outPath = Paths.get(TMPDIR, "test_ecb_1_2.out");
		byte[] inData = HexString.parse("DAD0BC105BCD60F44B5E86DF21C86E7E85F7AD59268F6C527045AF291ABBB2D0");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-ecb",
				"-d", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED622F5EE078671AED"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		assertEquals(16, result.length);
		String actual = new String(result);
		System.out.printf("#%s\n", actual);
		assertEquals(DATA1, actual);
	}

	@Test
	public void test_ecb_2_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ecb_2_1.in");
		Path outPath = Paths.get(TMPDIR, "test_ecb_2_1.out");
		byte[] inData = DATA2.getBytes();
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-ecb",
				"-e", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED622F5EE078671AED"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("DAD0BC105BCD60F44B5E86DF21C86E7ED47E47A949514837921F398CF2878899", actual);
	}

	@Test
	public void test_ecb_2_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ecb_2_2.in");
		Path outPath = Paths.get(TMPDIR, "test_ecb_2_2.out");
		byte[] inData = HexString.parse("DAD0BC105BCD60F44B5E86DF21C86E7ED47E47A949514837921F398CF2878899");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-ecb",
				"-d", inPath.toString(),
				"-o", outPath.toString(),
				"-K", "xyzzy"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		assertEquals(17, result.length);
		String actual = new String(result);
		System.out.printf("#%s\n", actual);
		assertEquals(DATA2, actual);
	}

	@Test
	public void test_ecb_3_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ecb_3_1.in");
		Path outPath = Paths.get(TMPDIR, "test_ecb_3_1.out");
		byte[] inData = DATA3.getBytes();
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-192-ecb",
				"-e", inPath.toString(),
				"-o", outPath.toString(),
				"-K", "xyzzy"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("3DA412BFA0D645A0708389D59BFC6DFCAC1CC582011F02E946212B556ABDCAFA23E4049C05C3DE3B7B4D0F5E8D684C013FE749491AAF2F948E382083F2210C07D13F926A74A0EBADC59505B2F58BA5E8E2EBECDBA276F3DC84AB4F9F22EBCAB5A4109EFBCF64749952733E7D749A5CC6A5F2CF40B976E2837482657B6B21EF8D", actual);
	}

	@Test
	public void test_ecb_3_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ecb_3_2.in");
		Path outPath = Paths.get(TMPDIR, "test_ecb_3_2.out");
		byte[] inData = HexString.parse("3DA412BFA0D645A0708389D59BFC6DFCAC1CC582011F02E946212B556ABDCAFA23E4049C05C3DE3B7B4D0F5E8D684C013FE749491AAF2F948E382083F2210C07D13F926A74A0EBADC59505B2F58BA5E8E2EBECDBA276F3DC84AB4F9F22EBCAB5A4109EFBCF64749952733E7D749A5CC6A5F2CF40B976E2837482657B6B21EF8D");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-192-ecb",
				"-d", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = new String(result);
		System.out.printf("#%s\n", actual);
		assertEquals(DATA3, actual);
	}

	@Test
	public void test_ecb_4_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ecb_4_1.in");
		Path outPath = Paths.get(TMPDIR, "test_ecb_4_1.out");
		byte[] inData = DATA4.getBytes();
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-128-ecb",
				"-e", inPath.toString(),
				"-o", outPath.toString(),
				"-K", "xyzzy"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("2D84DB6C70C7D74A193AD5AA5E3916A5B92B4702CE98346F6E73DE64B42A2D62A4E39AF48FE2F75DCCEA9091B6C7C45F7576995E907A8BDBD05D7419AA766A331261149BA9B5CE7E1A7E26D6ECAC718864D8B794865876075F0942FC929C29FD", actual);
	}

	@Test
	public void test_ecb_4_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ecb_4_2.in");
		Path outPath = Paths.get(TMPDIR, "test_ecb_4_2.out");
		byte[] inData = HexString.parse("2D84DB6C70C7D74A193AD5AA5E3916A5B92B4702CE98346F6E73DE64B42A2D62A4E39AF48FE2F75DCCEA9091B6C7C45F7576995E907A8BDBD05D7419AA766A331261149BA9B5CE7E1A7E26D6ECAC718864D8B794865876075F0942FC929C29FD");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-128-ecb",
				"-d", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = new String(result);
		System.out.printf("#%s\n", actual);
		assertEquals(DATA4, actual);
	}

	@Test
	public void test_cfb_1_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cfb_1_1.in");
		Path outPath = Paths.get(TMPDIR, "test_cfb_1_1.out");
		byte[] inData = DATA1.getBytes();
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-cfb",
				"-e", inPath.toString(),
				"-o", outPath.toString(),
				"-K", "xyzzy",
				"-I", "20241210"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("49C0822F2DDDEF8FC9A2DA65F3777502", actual);
	}

	@Test
	public void test_cfb_1_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cfb_1_2.in");
		Path outPath = Paths.get(TMPDIR, "test_cfb_1_2.out");
		byte[] inData = HexString.parse("49C0822F2DDDEF8FC9A2DA65F3777502");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-cfb",
				"-d", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED622F5EE078671AED",
				"-i", "B87E2F0E1BEB474894C501960ECBE847"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		assertEquals(16, result.length);
		String actual = new String(result);
		System.out.printf("#%s\n", actual);
		assertEquals(DATA1, actual);
	}

	@Test
	public void test_cfb_2_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cfb_2_1.in");
		Path outPath = Paths.get(TMPDIR, "test_cfb_2_1.out");
		byte[] inData = DATA2.getBytes();
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-cfb",
				"-e", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED622F5EE078671AED",
				"-i", "B87E2F0E1BEB474894C501960ECBE847"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("49C0822F2DDDEF8FC9A2DA65F377750267", actual);
	}

	@Test
	public void test_cfb_2_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cfb_2_2.in");
		Path outPath = Paths.get(TMPDIR, "test_cfb_2_2.out");
		byte[] inData = HexString.parse("49C0822F2DDDEF8FC9A2DA65F377750267");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-cfb",
				"-d", inPath.toString(),
				"-o", outPath.toString(),
				"-K", "xyzzy",
				"-I", "20241210"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		assertEquals(17, result.length);
		String actual = new String(result);
		System.out.printf("#%s\n", actual);
		assertEquals(DATA2, actual);
	}

	@Test
	public void test_cfb_3_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cfb_3_1.in");
		Path outPath = Paths.get(TMPDIR, "test_cfb_3_1.out");
		byte[] inData = DATA3.getBytes();
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-192-cfb",
				"-e", inPath.toString(),
				"-o", outPath.toString(),
				"-K", "xyzzy",
				"-I", "20241210"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("B7B85D38B7533D8D2A98C2F35097E39B8162F67205B233B7AC820B3E6012A1AEA78E8E781518278A5839F42BA21DAE9801FC078945354004285CBF2510C8A31830A9D50CB4F12C4E2562F1BFAD02B915CE7715AEEF4EFD1861E4BE66E4D224B0ACAEF75D7CFFAD24F97222CB130460B6DABD3EE8E718391CD0", actual);
	}

	@Test
	public void test_cfb_3_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cfb_3_2.in");
		Path outPath = Paths.get(TMPDIR, "test_cfb_3_2.out");
		byte[] inData = HexString.parse("B7B85D38B7533D8D2A98C2F35097E39B8162F67205B233B7AC820B3E6012A1AEA78E8E781518278A5839F42BA21DAE9801FC078945354004285CBF2510C8A31830A9D50CB4F12C4E2562F1BFAD02B915CE7715AEEF4EFD1861E4BE66E4D224B0ACAEF75D7CFFAD24F97222CB130460B6DABD3EE8E718391CD0");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-192-cfb",
				"-d", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED",
				"-i", "B87E2F0E1BEB474894C501960ECBE847"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = new String(result);
		System.out.printf("#%s\n", actual);
		assertEquals(DATA3, actual);
	}

	@Test
	public void test_cfb_4_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cfb_4_1.in");
		Path outPath = Paths.get(TMPDIR, "test_cfb_4_1.out");
		byte[] inData = DATA4.getBytes();
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-128-cfb",
				"-e", inPath.toString(),
				"-o", outPath.toString(),
				"-K", "xyzzy",
				"-I", "20241210"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("5604E5FFC8A5954F08549377ABFE0DE26DB2976DD7E89A051B347C06FF207F32853F522EC713840903A702F5EF9BB4791E3E12140B7201A0732D298F47F4229FACC86BFD0CDC34BA329136985FFFCAD6839777285C4526", actual);
	}

	@Test
	public void test_cfb_4_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cfb_4_2.in");
		Path outPath = Paths.get(TMPDIR, "test_cfb_4_2.out");
		byte[] inData = HexString.parse("5604E5FFC8A5954F08549377ABFE0DE26DB2976DD7E89A051B347C06FF207F32853F522EC713840903A702F5EF9BB4791E3E12140B7201A0732D298F47F4229FACC86BFD0CDC34BA329136985FFFCAD6839777285C4526");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-128-cfb",
				"-d", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE",
				"-i", "B87E2F0E1BEB474894C501960ECBE847"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = new String(result);
		System.out.printf("#%s\n", actual);
		assertEquals(DATA4, actual);
	}

	@Test
	public void test_ofb_1_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ofb_1_1.in");
		Path outPath = Paths.get(TMPDIR, "test_ofb_1_1.out");
		byte[] inData = DATA1.getBytes();
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-ofb",
				"-e", inPath.toString(),
				"-o", outPath.toString(),
				"-K", "xyzzy",
				"-I", "20241210"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("496B9D89A42BA31D86D87A378F375B52", actual);
	}

	@Test
	public void test_ofb_1_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ofb_1_2.in");
		Path outPath = Paths.get(TMPDIR, "test_ofb_1_2.out");
		byte[] inData = HexString.parse("496B9D89A42BA31D86D87A378F375B52");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-ofb",
				"-d", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED622F5EE078671AED",
				"-i", "B87E2F0E1BEB474894C501960ECBE847"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		assertEquals(16, result.length);
		String actual = new String(result);
		System.out.printf("#%s\n", actual);
		assertEquals(DATA1, actual);
	}

	@Test
	public void test_ofb_2_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ofb_2_1.in");
		Path outPath = Paths.get(TMPDIR, "test_ofb_2_1.out");
		byte[] inData = DATA2.getBytes();
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-ofb",
				"-e", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED622F5EE078671AED",
				"-i", "B87E2F0E1BEB474894C501960ECBE847"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("496B9D89A42BA31D86D87A378F375B521F", actual);
	}

	@Test
	public void test_ofb_2_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ofb_2_2.in");
		Path outPath = Paths.get(TMPDIR, "test_ofb_2_2.out");
		byte[] inData = HexString.parse("496B9D89A42BA31D86D87A378F375B521F");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-ofb",
				"-d", inPath.toString(),
				"-o", outPath.toString(),
				"-K", "xyzzy",
				"-I", "20241210"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		assertEquals(17, result.length);
		String actual = new String(result);
		System.out.printf("#%s\n", actual);
		assertEquals(DATA2, actual);
	}

	@Test
	public void test_ofb_3_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ofb_3_1.in");
		Path outPath = Paths.get(TMPDIR, "test_ofb_3_1.out");
		byte[] inData = DATA3.getBytes();
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-192-ofb",
				"-e", inPath.toString(),
				"-o", outPath.toString(),
				"-K", "xyzzy",
				"-I", "20241210"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("B77F0FDC4A6666B3FA0C15A9499B2C42FB271D59CF665B48CB5A40308777203BAB4DB4D9F18F69BABE1F1F9E44DCE2A1F031A6ADEC9BF7B89DF09496E56E4435C4377DD97E767E84CD2C72A82772F2E70ADA11EE251CFEA8703E2DF46CB25A0AE441F43CF8C31832EBB36E39613C323D0D1A9DCED7C70B415D", actual);
	}

	@Test
	public void test_ofb_3_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ofb_3_2.in");
		Path outPath = Paths.get(TMPDIR, "test_ofb_3_2.out");
		byte[] inData = HexString.parse("B77F0FDC4A6666B3FA0C15A9499B2C42FB271D59CF665B48CB5A40308777203BAB4DB4D9F18F69BABE1F1F9E44DCE2A1F031A6ADEC9BF7B89DF09496E56E4435C4377DD97E767E84CD2C72A82772F2E70ADA11EE251CFEA8703E2DF46CB25A0AE441F43CF8C31832EBB36E39613C323D0D1A9DCED7C70B415D");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-192-ofb",
				"-d", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED",
				"-i", "B87E2F0E1BEB474894C501960ECBE847"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = new String(result);
		System.out.printf("#%s\n", actual);
		assertEquals(DATA3, actual);
	}

	@Test
	public void test_ofb_4_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ofb_4_1.in");
		Path outPath = Paths.get(TMPDIR, "test_ofb_4_1.out");
		byte[] inData = DATA4.getBytes();
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-128-ofb",
				"-e", inPath.toString(),
				"-o", outPath.toString(),
				"-K", "xyzzy",
				"-I", "20241210"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("56ADB67F2061E7892470D9245EEA42241C3571DBF4E55F9376DA3B74212477FF371830F890BAC8AA2F2804E856AE4CB8C5CF26C3246B23A26C2CC1B9B311C9112AFF8F920839975658817F3CE4A08DC061116113DB1D63", actual);
	}

	@Test
	public void test_ofb_4_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ofb_4_2.in");
		Path outPath = Paths.get(TMPDIR, "test_ofb_4_2.out");
		byte[] inData = HexString.parse("56ADB67F2061E7892470D9245EEA42241C3571DBF4E55F9376DA3B74212477FF371830F890BAC8AA2F2804E856AE4CB8C5CF26C3246B23A26C2CC1B9B311C9112AFF8F920839975658817F3CE4A08DC061116113DB1D63");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-128-ofb",
				"-d", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE",
				"-i", "B87E2F0E1BEB474894C501960ECBE847"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = new String(result);
		System.out.printf("#%s\n", actual);
		assertEquals(DATA4, actual);
	}

}
