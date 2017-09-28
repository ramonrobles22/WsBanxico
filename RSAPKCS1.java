package com.mx.bancoazteca.encrypt;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RSAPKCS1 {
	public final static String PRIVATE_KEY = "KeyPair/AZTECA.key";
	public final static String PUBLIC_KEY = "KeyPair/pubKey.key";

	public static void main(String[] args) throws Exception {

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		//Se obtiene la Llave privada
		KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
		PrivateKey priv = generatePrivateKey(factory, PRIVATE_KEY);
		PublicKey pub = generatePublicKey(factory, PUBLIC_KEY);

		byte[] input = "EBtXizQ1x96+OgDq+9BASU4O6r9WTwxOgQL4ZjBOswbSgTos/y/pD1cJyrYmE+OCTO3t1OONPrChdlKyQUPQNW6VqQ8P94tg5KvNv10a1YoYsrz70vWogHsHcjGhBLfxQNDnTs8RaOxI5ItKWmn2IQNGb7rteh9ZAxx+YWa2MxNz3dMQFx/w1DNmYaQJmlrzfX39UQO5Ww+xdwuhVymXXsyK+Do5yYzKkn4mt3UpwheNvi5ekIBAV720+TQc/5w0LZ1E0aw1rv69tsSDhNCXrf6dpllm6miAIHhOyIZigqxI/0BZZjqMFCfRyx+KuSBm4pGFOg==".getBytes();
		//byte[] input = "Laura Toledo Guzman".getBytes();
		Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding","BC");


		String decript=new String(Base64.decodeBase64(input));

		System.out.println("*****Generate Binary File****************");
		//Encode to Base64 and save into binary file
		FileOutputStream fos = new FileOutputStream("KeyPair/test-decrypt");
		fos.write(decript.getBytes());
		fos.close();
		System.out.println("Your file decoded is ready.");

		/*cipher.init(Cipher.ENCRYPT_MODE, pub);		
		byte[] cipherText = cipher.doFinal(input);
		System.out.println("cipher: " + new String(Base64.encodeBase64(cipherText)));*/

		cipher.init(Cipher.DECRYPT_MODE, priv);

		System.out.println("Bloq size "+cipher.getBlockSize());
		System.out.println("Bloq size decript "+decript.getBytes().length);

		//byte[] plainText = cipher.doFinal(cipherText);
		byte[] plainText = cipher.doFinal(decript.getBytes());
		System.out.println("Tamaño respuesta "+plainText.length);
		System.out.println("plain : " + new String(plainText,"UTF8"));

		fos = new FileOutputStream("KeyPair/test-decrypt-plaintext");
		fos.write(plainText);
		fos.close();
		System.out.println("Your file decoded is ready.");
	}
	private static PrivateKey generatePrivateKey(KeyFactory factory, String filename) throws InvalidKeySpecException, FileNotFoundException, IOException {
		PemFile pemFile = new PemFile(filename);
		byte[] content = pemFile.getPemObject().getContent();
		PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
		return factory.generatePrivate(privKeySpec);
	}
	private static PublicKey generatePublicKey(KeyFactory factory, String filename) throws InvalidKeySpecException, FileNotFoundException, IOException {
		PemFile pemFile = new PemFile(filename);
		byte[] content = pemFile.getPemObject().getContent();
		X509EncodedKeySpec  pubKeySpec = new X509EncodedKeySpec(content);
		return factory.generatePublic(pubKeySpec);
	}

//	private static void verifySign(PublicKey pubKeySender) throws IOException{
//		Signature myVerifySign = Signature.getInstance("SHA256withRSA");
//		myVerifySign.initVerify(pubKeySender);
//		myVerifySign.update(strMsgToSign.getBytes());
//
//		boolean verifySign = myVerifySign.verify(byteSignedData);
//		if (verifySign == false)
//		{
//			System.out.println(" Error in validating Signature ");
//		}
//
//		else
//			System.out.println(" Successfully validated Signature ");
//	}
}