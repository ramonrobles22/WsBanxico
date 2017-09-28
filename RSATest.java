package com.mx.bancoazteca.encrypt;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RSATest {
	public final static String PRIVATE_KEY = "KeyPair/AZTECA.key";

	public static void main(String[] args) {
		//Se lee la llave PEM con Bouncy Castle
		Security.addProvider(new BouncyCastleProvider());
		String cadena="|27/09/2017 13:53:25|LAURA TOLEDO GUZMAN|BEL090908DWFR7|moral|";
		//String cadena="|iRTthwn+Cxj5K4RoxrlcYstolxCEFr2D3pnP1rKZjOnq2dbGB7qwqGxkfRVVRwKeWjWjOwPDw0bkkD29HK6phHtRNoHbYWp4ok98IPxs05EH7zTzkNCAilfrclfpOzjE8slERV5dEBDWdk03k5Ad4TpHp9AYwPOBdm1Tvmqm+Jo4KnEqeBefuyTSBtvcpwhN/aeAYWlBEFKaGY5Zn2N1s3tVFbi1VrZND2SFx8TChIa/alcTJw93aw1mSOiH6QJL1oU1df4/dDDITxu++fh3paoUVcUi3/XHmEiz9JjqPOpipFw7gtLGFk7gJrQ5J42iyn35SpCwXuiFGKetjwGO6HPt6+lcvQsNXFmWLM7DdOmATx1SQrZ9zxhTbaw+ade9rACqG6AQDCAH6y9pNd4kVs/XyNnsyV31y7ITQgeCbPMqqcI93RIJL3E8gNchEzb0bS4GnSstVcbG/VSNpAp6a0ZnxJylXGshrL4+EaN3QXcobQFObgVxGlnFPKxOOjqxFp8gpOiUY0i/k509aU67KPfq5erYhJkR2omQqBzyeKg2XPMJjUN33FuhOkpLsvxNBJ3J7USli3rmFLLy/Xsv3NCphMQEvod26TH0w4mb9I9V8wbbjCD4lDM4/8OvRjJNqs+RxEz1hs2ybJYs14X2YSbVbRxVd5k6cvIBw+LGSp70QzU0pytw7KbmkVFWnheaNqjc66/vd9PdkilFremCyE3pz/6cp16bhvPKnYVERojz8zLKEodZl9ubeezKyaPRLFUYWjY3xFPUlO0UUyWfbCpCOo8KQ9KdKsszeoiI7rfV97xoK37GiaykTg1xAk+EZaS9Zeek/oGEMUt4fC9SVjD7GVi7J9L6ca5FRMa/828EjgbDFhSbX8nZ1SZtCEi2f0KfWGUDa8XySKVqUrGBPDz6kg6Z9e4SM0ioBY+5xnmsyFYxDf/cz6jRh0nCalCOgl8rqE5nbonRwmqRQMRIJJbv4i4/pMSlhDIBb45rEzUZ+MGRwa6c3Wi9+yOaoBhxa2b9RsZun/XnflpemN+fIRNLi3jTYtj1yk2QGSUUwEnnehfitrNqJwtSB+hXgaJ8y2bRLLTSrziZOwES/DUA9+TWi/P5juaU0WmClDPiEdJFiLOzjbamkXf2npVT6vP5stBwjc8vLlFj2qa8dCk8813dAC3kMpzA/NE8we/ok1sbVQBfhsiP0x899neWLQl+6Rg9kyeBLI87w3ywtQfqU/jxDc4T6eARDUPNslRId1Sa61sAMnAujQL04AI+0ftPW0H/eJITRdUeBxfUd6QURbr54QogjaRzqrQOGw8CMMEREOz7BowwS3Ff/RCHN2d2Ea4WHp6hKnZhURCi9hxfLaH76t0nnwwrCxv1x2bbF2Ql1oFaAKS1xPnaEuuFAZb41vpkrTX2uX22+NabafgoWOBH9Qd5IiBSmf3X7d5WjQ4ntWxsaZcDhTWgWwgss+qE+UqaFHNVb5lqy8G8K43LmAj7V2twQfVTdW56ASd9qM+XdE/iPtM1qzWs2Z+KohqbDfbW9C24WhKVuPewMCQx9Y5MicbZK/Xi+vBJgxaznwM9JjjK+vlope7ZTkKI0oXYX/83EI2483UPD3tlb9OqBt6nap23O8SpMLXemPiJeUk=|vUWSlQuK+GNUpFY/pAA9oHwauDWsUZ7U8D64nGIDIwWSRaLN90s/ostzw5iRJK6yNqV5TNA69UhzaqdxpZ0J1A40ZR4vFxo/xIDAUzwBHjZQQWcBZ2z1rqu/0c3fmRsFUliGGOFnQXaTI3Cs9B4pEhQJJSENJ7St/Qdy4os3XawSpjV3g123CFJ4jXiTd7V0IT6ht+zrLFrtSfv55o9QZrjbGULeDrpu5FhsdzotI8ZwUFE9e1g4NHmn5zMK/jDGbOcKicnUbQBQZlJczcE1KLF6UUvAJkMFoE0HU3EKFdl59YLE2MzJG2WtZ+waP+F5+ZvTHAyjNLNqcHuxM7x/8A==|27/09/2017 10:28:07|f|";

		try {
			//Se obtiene la Llave privada
			KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
			PrivateKey priv = generatePrivateKey(factory, PRIVATE_KEY);

			//Se váilda el formato y el algoritmo de la llave (PKCS#8 y RSA)
			System.out.println("Format: "+priv.getFormat());
			System.out.println("Algorithm: "+priv.getAlgorithm());

			//Se comprueba su estructura
			System.out.println(String.format("Instantiated private key: %s", priv));

			//Se firma
			byte [] firma=sign(priv,cadena);

			//Se escribe el archivo binario
			writeFileEncodedB64(firma);

			//Se lee el archivo para obtener el mensaje firmado
			StringBuilder dataSinged=getSignedDatafromFile();

			System.out.println("Data singed: "+dataSinged);

			/*---------------------------Termina la firma--------------*/
			StringBuilder dataSingedResponse = new StringBuilder();;
			dataSingedResponse.append("JUdJtWmRjBMq2A0t+30d22IKJ0wEVT3bt39q97+giJITnf4p1UrKTgIAqmJgXWH72Gfo+9IVrnmDMHDbeX+yrORzagkiSzy+GVAgLqLIrSCBJItcoNn/UfuxEtOnPNCvu2cxSdQNcKOyVRt5OZpGN1oW+WNim2OCm5OSm1Y82Lslg1bJzzj1A6LYhSPUMQtVtyeTgQO1CqH+ahw373gg3NmFwqbldQUfjAiNB2pwF2O8TIDU6sVEfnRYoDpwyTh0g19Mt1cA1UVzPHo6ey/UhPbpolom32MlqZq5T4mkNXZzttdtoMyJm+MId/+vSZbpqPY2182AeT3hMwqFkrT6rQ==");
			//Se realiza la decodificación de B64
			writeFileDecodedB64(dataSingedResponse);

			//Se desencripta el contenido 
			//decryptResponse(priv);

		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}


	}

	private static PrivateKey generatePrivateKey(KeyFactory factory, String filename) throws InvalidKeySpecException, FileNotFoundException, IOException {
		PemFile pemFile = new PemFile(filename);
		byte[] content = pemFile.getPemObject().getContent();
		PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
		return factory.generatePrivate(privKeySpec);
	}

	private static byte[] sign(PrivateKey key, String data)throws GeneralSecurityException {
		System.out.println("*****Sign****************");
		Signature signature = Signature.getInstance("SHA256withRSA");
		System.out.println("Proveider of Sign: "+signature.getProvider());
		System.out.println("Algorithm of Sing: "+signature.getAlgorithm());
		signature.initSign(key);

		signature.update(data.getBytes());
		
		return signature.sign();
	}

	private static void writeFileEncodedB64(byte [] firma) throws IOException{
		System.out.println("*****Generate Binary File****************");
		//Encode to Base64 and save into binary file
		FileOutputStream fos = new FileOutputStream("KeyPair/signature-java");
		fos.write(Base64.encodeBase64(firma));
		fos.close();
		System.out.println("Your file is ready.");
	}

	private static StringBuilder getSignedDatafromFile() throws IOException{
		System.out.println("*****Getting DataSing Info****************");
		//Se realiza la lectura del archivo Binario codificado
		String content;
		StringBuilder sbuilder = new StringBuilder();
		FileReader f = new FileReader("KeyPair/signature-java");
		BufferedReader b = new BufferedReader(f);
		while((content = b.readLine())!=null) {
			sbuilder.append(content);
		}
		b.close();
		return sbuilder;
	}

	private static void writeFileDecodedB64(StringBuilder dataSinged) throws IOException{
		System.out.println("*****Generate Binary File****************");
		//Encode to Base64 and save into binary file
		FileOutputStream fos = new FileOutputStream("KeyPair/signature-java-decode");
		fos.write(Base64.decodeBase64(dataSinged.toString().getBytes()));
		fos.close();
		System.out.println("Your file decoed is ready.");
	}

	private static void decryptResponse(PrivateKey priv){
		try {
			byte[] dataFromFile=getResponseDatafromFile();
			String input=dataFromFile.toString();
			System.out.println("Data form file "+input);
			Cipher cipher = Cipher.getInstance("RSA/none/PKCS1Padding","BC");

			cipher.init(Cipher.DECRYPT_MODE, priv);
			System.out.println("Algorithm "+cipher.getAlgorithm());
			System.out.println("Bloq size "+cipher.getBlockSize());
			System.out.println("Proveider "+cipher.getProvider());
			
			byte[] plainText = cipher.doFinal(input.getBytes());
			System.out.println("plain : " + new String(plainText));
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
	}

	private static byte [] getResponseDatafromFile() throws IOException{
		System.out.println("*****Getting ResponseDataFromFile ****************");
		//Se realiza la lectura del archivo Binario codificado
		String content;
		StringBuilder sbuilder = new StringBuilder();
		FileInputStream fileInput = new FileInputStream("KeyPair/signature-java-decode");
		BufferedInputStream bufferedInput = new BufferedInputStream(fileInput);
		byte [] array = new byte[10000];
		int leidos = bufferedInput.read(array);
		
		// Cierre de los ficheros
		bufferedInput.close();
		
		return array;
	}
	
}