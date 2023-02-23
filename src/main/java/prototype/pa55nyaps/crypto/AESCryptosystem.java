/*
PA55 NYAPS Java Reference Implementation

Copyright 2015 Anirban Basu

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package prototype.pa55nyaps.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.util.zip.ZipException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Base64;

import prototype.pa55nyaps.dataobjects.Ciphertext;

/**
 * A 128-bit AES cryptosystem helper.
 * 
 * @author Juan Camilo Corena, Anirban Basu
 *
 */
public class AESCryptosystem {
	private static final String BYTE_ENCODING = "UTF-8";
	private static final String AES_MODE_CTR = "AES/CTR/NoPadding";
    private static int keySize = 16; //bytes
    private static int hmacKeySize = 32; //bytes
    private static int saltSize = 16; //bytes
    private static int ivSize = 16; //bytes
    private static final String SECRET_KEY_ALGO = "AES";
    private static final String HMAC_ALGO = "HmacSHA256";
    private static AESCryptosystem singletonInstance = null;
    
    public static synchronized AESCryptosystem getInstance() {
    	if(singletonInstance == null) {
    		singletonInstance = new AESCryptosystem();
    	}
    	return singletonInstance;
    }
    
    private AESCryptosystem() {};
    
    private byte[] generateRandomBytes(int size) { //size is in bytes
    	SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[size]; 
        random.nextBytes(bytes);
        return bytes;
    }
    
    private String generateMacForData(byte[] data, byte[] key) throws NoSuchAlgorithmException,
    	InvalidKeyException, NoSuchProviderException {
    	SecretKeySpec keySpec = new SecretKeySpec(key, HMAC_ALGO);
    	Mac mac = Mac.getInstance(HMAC_ALGO);
    	mac.init(keySpec);
    	return Base64.toBase64String(mac.doFinal(data));
    }
    
    private byte[] compressBytes(byte[] data) throws IOException {
    	ByteArrayOutputStream memoryStream = new ByteArrayOutputStream(data.length);
		GZIPOutputStream gzipStream = new GZIPOutputStream(memoryStream);
		gzipStream.write(data, 0, data.length);
		gzipStream.finish();
		gzipStream.close();
		byte[] compressed = memoryStream.toByteArray();
		memoryStream.close();
		byte[] gzipBuffer = new byte[compressed.length + 4];
		System.arraycopy(compressed, 0, gzipBuffer, 4, compressed.length);
		byte [] dataLengthBuffer = new byte [4];
		dataLengthBuffer [0] = (byte) data.length;
		dataLengthBuffer [1] = (byte)((data.length >> 8) & 0xFF);
		dataLengthBuffer [2] = (byte)((data.length >> 16) & 0xFF);
		dataLengthBuffer [3] = (byte)((data.length >> 24) & 0xFF);
		System.arraycopy(dataLengthBuffer, 0, gzipBuffer, 0, 4);
		//ByteBuffer dataLengthBuffer = ByteBuffer.allocate(4);
		//dataLengthBuffer.order(ByteOrder.LITTLE_ENDIAN);
		//System.arraycopy(dataLengthBuffer.putInt(data.length).array(), 0, gzipBuffer, 0, 4);
		return gzipBuffer;
    }
    
    private byte[] decompressBytes(byte[] data) throws IOException {
    	ByteArrayInputStream memoryStream = new ByteArrayInputStream(data, 4, data.length - 4);
		GZIPInputStream gzipStream;
		try {
			//ByteBuffer dataLengthBuffer = ByteBuffer.wrap(data, 0, 4);
			//dataLengthBuffer.order(ByteOrder.LITTLE_ENDIAN);
			//int dataLength = dataLengthBuffer.getInt();
			int dataLength = (((int)data[3] & 0xFF) << 24) | (((int)data[2] & 0xFF) << 16) | (((int)data[1] & 0xFF) << 8) | ((int)data[0] & 0xFF);
			gzipStream = new GZIPInputStream(memoryStream, dataLength); //specify the buffer length otherwise, it will be initialised with a default buffer size and the read method will only read that much
			byte[] uncompressedData = new byte[dataLength];
			gzipStream.read(uncompressedData, 0, dataLength);
			gzipStream.close();
			memoryStream.close();
			return uncompressedData;
		}
		catch(ZipException e) {
			//this is most likely not supported, pass the data as is
			return data;
		}
    }
   
    /**
     * Encrypts a plaintext with a password and generates the corresponding ciphertext with a 256-bit
     * HMAC. This method expands the given password using a password-based key derivation function to generate
     * two keys making use of a random salt. The first key is used the encrypt the plaintext in AES counter
     * mode using a random initialisation vector while the other key is used to generate the 256-bit HMAC.
     * 
     * @param plaintext
     * @param password
     * @return a ciphertext with HMAC
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidParameterSpecException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchProviderException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws IOException 
     */
    public Ciphertext encryptWithHmac(String plaintext, String password, boolean compress) throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidKeyException, InvalidParameterSpecException, InvalidAlgorithmParameterException, NoSuchProviderException, IllegalBlockSizeException, BadPaddingException, IOException {
    	byte[] plainBytes;
    	if(compress) {
			plainBytes = compressBytes (plaintext.getBytes(BYTE_ENCODING));
		} else {
			plainBytes = plaintext.getBytes(BYTE_ENCODING);
		}
		//get random salt
		byte[] salt = generateRandomBytes(saltSize);
		//get random iv
		byte[] randomIV = generateRandomBytes(ivSize);
		//generate concatenated keys and split them into relevant keys
    	byte[] concatenatedKeys = PBKDF2StreamGenerator.generateStream(
    			password.getBytes(BYTE_ENCODING), salt, (keySize + hmacKeySize));
    	byte[] encryptionKey = Arrays.copyOfRange(concatenatedKeys, 0, keySize);
	    byte[] hmacKey = Arrays.copyOfRange(concatenatedKeys, keySize, (keySize + hmacKeySize));
		//setup the encryption cipher to encrypt data
	    Cipher dataEncryptionCipher = Cipher.getInstance(AES_MODE_CTR);
	    dataEncryptionCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encryptionKey, SECRET_KEY_ALGO), new IvParameterSpec(randomIV));
	    //create empty result data structure
	    Ciphertext result = new Ciphertext();
	    //encrypt the data
	    byte[] rawCiphertext = dataEncryptionCipher.doFinal(plainBytes);
	    result.setCiphertext(Base64.toBase64String(rawCiphertext));
	    result.setSalt(Base64.toBase64String(salt));
	    //encrypt the random iv
	    result.setIv(Base64.toBase64String(randomIV));
	    //generate and set the hmac of the ciphertext concatenated with the encrypted iv and the salt
	    byte[] concatenatedHmacData = new byte[salt.length + randomIV.length + rawCiphertext.length];
	    System.arraycopy(salt, 0, concatenatedHmacData, 0, salt.length);
	    System.arraycopy(randomIV, 0, concatenatedHmacData, salt.length, randomIV.length);
	    System.arraycopy(rawCiphertext, 0, concatenatedHmacData, salt.length + randomIV.length, rawCiphertext.length);
	    result.setHmac(generateMacForData(concatenatedHmacData, hmacKey));
	    result.setKeySize(keySize);
	    result.setSaltSize(saltSize);
	    result.setIvSize(ivSize);
	    result.setHmacKeySize(hmacKeySize);
	    return result;
    }
    
    /**
     * Given a ciphertext with its HMAC, this method decrypts it with the given password. The password is expanded using
     * the stored salt and a password-based key derivation function to generate two keys: the first one is used for the 
     * decryption while the second one is used to validate the HMAC. Decryption does not start until the HMAC is verified.
     * Decryption runs in AES counter mode with the initialisation vector stored in the ciphertext object.
     *  
     * @param ciphertext
     * @param password
     * @return the plaintext
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeySpecException
     * @throws NoSuchProviderException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws IOException 
     */
    public String decryptWithHmac(Ciphertext ciphertext, String password) throws InvalidKeyException, InvalidAlgorithmParameterException,
    	NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, NoSuchProviderException, 
    	IllegalBlockSizeException, BadPaddingException, IOException {
    	//decode from Base64
    	byte[] salt = Base64.decode(ciphertext.getSalt());
    	byte[] randomIV = Base64.decode(ciphertext.getIv());
    	byte[] rawCiphertext = Base64.decode(ciphertext.getCiphertext());
    	if(rawCiphertext.length==0 || salt.length == 0 || randomIV.length == 0) {
    		//the salt or IV are never empty (see the encryptWithHmac method), so if these are empty then they must have been tampered with.
    		throw new SecurityException("At least one of: the ciphertext, the salt or the random initialisation vector is empty, which is unexpected. Decryption aborted.");
    	}
    	//generate concatenated keys and split them into relevant keys
    	byte[] concatenatedKeys = PBKDF2StreamGenerator.generateStream(
    			password.getBytes(BYTE_ENCODING), salt, (ciphertext.getKeySize() + ciphertext.getHmacKeySize()));
    	byte[] encryptionKey = Arrays.copyOfRange(concatenatedKeys, 0, ciphertext.getKeySize());
	    byte[] hmacKey = Arrays.copyOfRange(concatenatedKeys, ciphertext.getKeySize(), (ciphertext.getKeySize() + ciphertext.getHmacKeySize()));
    	//generate secret key
        SecretKeySpec secret = new SecretKeySpec(encryptionKey,SECRET_KEY_ALGO);
        if(ciphertext.getHmac()!=null && ciphertext.getHmac().length()>0) { //short-circuit evaluation to make sure hmac is not null!
        	//verify hmac if it is present
        	byte[] concatenatedHmacData = new byte[salt.length + randomIV.length + rawCiphertext.length];
        	System.arraycopy(salt, 0, concatenatedHmacData, 0, salt.length);
    	    System.arraycopy(randomIV, 0, concatenatedHmacData, salt.length, randomIV.length);
    	    System.arraycopy(rawCiphertext, 0, concatenatedHmacData, salt.length + randomIV.length, rawCiphertext.length);
	        String hmac = generateMacForData(concatenatedHmacData, hmacKey);
	        if(hmac.compareTo(ciphertext.getHmac())!=0) {
	        	//do not proceed if this happens
	        	throw new SecurityException("The ciphertext and its parameters fail the message integrity test. Decryption aborted.");
	        }
        }
        //setup the data and parameter decryption ciphers
        Cipher dataDecryptionCipher = Cipher.getInstance(AES_MODE_CTR);
    	dataDecryptionCipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(randomIV));
    	//decrypt (and decompress, if necessary) the message
		return new String(decompressBytes (dataDecryptionCipher.doFinal(rawCiphertext)), BYTE_ENCODING);
    }
}