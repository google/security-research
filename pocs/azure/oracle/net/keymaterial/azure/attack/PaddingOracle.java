package net.keymaterial.azure.attack;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class PaddingOracle {
	private Oracle oracle;

	public PaddingOracle(Oracle oracle) {
		this.oracle = oracle;
	}

	public byte[] attack() {
		System.out.println("Attacker: starting");
		byte[] ciphertextWithoutIv = oracle.retrieveChallengeCiphertext();
		byte[] iv = oracle.retrieveChallengeIv();
		System.out.println("Attacker: challenge iv is " + toHex(iv) + ", ciphertext is " + toHex(ciphertextWithoutIv));
		if (!oracle.attemptDecryption(iv, ciphertextWithoutIv)) {
			System.err.println("Challenge ciphertext invalid");
			return new byte[0];
		}
		byte[] ciphertext = new byte[iv.length + ciphertextWithoutIv.length];
		for (int i = 0; i < iv.length; i++) {
			ciphertext[i] = iv[i];
		}
		for (int i = 0; i < ciphertextWithoutIv.length; i++) {
			ciphertext[i + iv.length] = ciphertextWithoutIv[i];
		}
		byte padding = findPadding(ciphertext);
		byte plaintext[] = new byte[ciphertext.length - 16 - padding];
		for (int i = 0; i < plaintext.length; i++) {
			guessByte(plaintext.length - i - 1, ciphertext, plaintext);
		}
		return plaintext;
	}

	private void guessByte(int index, byte ciphertext[], byte plaintext[]) {
		System.out.println("Attacker: guessing for index " + index);
		byte padding = (byte) (ciphertext.length - plaintext.length - 16);
		byte ciphertextMod[] = Arrays.copyOf(ciphertext, (index / 16 + 2) * 16);
		byte newPadding = (byte) (ciphertextMod.length - index - 16);
		for (int i = ciphertextMod.length - 16 - 1; i > index; i--) {
			ciphertextMod[i] = (byte) (ciphertextMod[i]
					^ (i < plaintext.length ? (plaintext[i] ^ newPadding) : (padding ^ newPadding)));
		}
		byte orig = ciphertextMod[index];
		for (int guess = 0; guess < 256; guess++) {
			ciphertextMod[index] = (byte) (orig ^ newPadding ^ guess);
			if (oracle.attemptDecryption(Arrays.copyOfRange(ciphertextMod, 0, 16),
					Arrays.copyOfRange(ciphertextMod, 16, ciphertextMod.length))) {
				plaintext[index] = (byte) guess;
				System.out.println("Attacker: Guess for index " + index + " found: " + toHex((byte) guess));
				return;
			}
		}
		throw new RuntimeException("No guess found!");
	}

	private byte findPadding(byte ciphertext[]) {
		byte xor = 0x01;
		System.out.println("Attacker: Looking for padding!");
		if (ciphertext.length % 16 != 0) {
			return (byte) 0xff;
		}
		for (byte padding = 0x01; padding <= 16; padding++) {
			if (padding + 16 >= ciphertext.length) {
				return 0x10;
			}
			byte modCiphertext[] = xorPlaintextByte(ciphertext.length - 16 - padding - 1, xor, ciphertext);
			System.out.println("Attacker: Checking for padding length " + padding);
			if (oracle.attemptDecryption(Arrays.copyOfRange(modCiphertext, 0, 16),
					Arrays.copyOfRange(modCiphertext, 16, modCiphertext.length))) {
				return padding;
			}
		}
		return (byte) 0xff;
	}

	private byte[] xorPlaintextByte(int index, byte xor, byte ciphertext[]) {
		if (ciphertext.length < index + 16) {
			throw new IndexOutOfBoundsException();
		}
		byte result[] = Arrays.copyOf(ciphertext, ciphertext.length);
		result[index] = (byte) (result[index] ^ xor);
		return result;
	}

	private String toHex(byte b) {
		int asInt = b & 255;
		String hex = Integer.toHexString(asInt);
		return (hex.length() == 1 ? "0" : "") + hex;
	}

	private String toHex(byte[] array) {
		List<String> list = new ArrayList<>();
		for (byte b : array) {
			list.add(toHex(b));
		}
		return String.join(" ", list);
	}
}
