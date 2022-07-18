package net.keymaterial.azure.attack;

public interface Oracle {
	byte[] retrieveChallengeCiphertext();
	byte[] retrieveChallengeIv();
	boolean attemptDecryption(byte[] iv, byte[] ciphertext);
	int getNumberOfGuesses();
}
