import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {
	private static SecureRandom _secureRandom = new SecureRandom();
	private final static BigInteger PUBLIC_KEY_E = new BigInteger("65537");
	private final static BigInteger PRIME_SEPARATION_CHECK = new BigInteger("2").pow(1000);
	static BigInteger p,q, phi, n, private_key, encryptedMessage,decryptedMessage;

	
	/** This class generates all the variables for RSA encryption (p, q, phi, n,p rivate key)
	 * @param minBitSize
	 */
	static void RSAgenerator(int minBitSize) {
		do {	// This loop generates phi =(p-1)(q-1) and verifies that it is relatively prime with our public key
			do {	// This loop uses probablePrime to find prime numbers of atleast 1536 bits and verifies that |p-q|> 2^1000
				p = BigInteger.probablePrime(minBitSize, _secureRandom);
				q = BigInteger.probablePrime(minBitSize, _secureRandom);
			}while((p.subtract(q)).abs().compareTo(PRIME_SEPARATION_CHECK)!=1);
			phi = (p.subtract(new BigInteger("1"))).multiply(q.subtract(new BigInteger("1")));
		}while(!relativelyPrime(phi, PUBLIC_KEY_E));
		n = p.multiply(q);	// n = pq
		private_key = PUBLIC_KEY_E.modInverse(phi);	// private = 1/(public*mod(phi))
		/*print statements for debugging/ see under the hood
		 * System.out.println("p = "+p+"\nq = "+q+"\nphi: "+ phi+"\nn: "+ n+"\nPrivate Key: "+private_key);*/
		// verification e*dmodphi = 1
		System.out.println("Verifying private_key by multiplicative inverse: " 
				+((PUBLIC_KEY_E.multiply(private_key)).mod(phi).equals(new BigInteger("1"))?"SUCCESS":"FAIL"));
	}
	
	
	/** Algorithm for comparing 2 integers for greatest common denominator (GCD)
	 */
	private static BigInteger gcd(BigInteger phi, BigInteger e) {
		BigInteger t;
		while(e.compareTo(new BigInteger("0")) != 0){
			t = phi;
			phi = e;
			e = t.mod(e);
		}
		return phi;
	}
	
	
	/** return true if phi and E have a GCD of 1
	 */
	private static boolean relativelyPrime(BigInteger phi, BigInteger E) {
		return gcd(phi,E).compareTo(new BigInteger("1")) == 0;
	}
	
	
	/** encrypts the (input^public key)mod n
	 * @param input
	 * @return
	 */
	public static BigInteger encrypt(BigInteger input) {
		return input.modPow(PUBLIC_KEY_E, n);
	}
	
	
	/** decrypts the (ciphertext^privateKey) mod n
	 * @param ciphertext
	 * @return
	 */
	public static BigInteger decrypt(BigInteger ciphertext) {
		return ciphertext.modPow(private_key, n);
	}
	
	
	/**Driver class
	 * With sample proof of concept
	 */
	public static void main(String[] args) {
		RSAgenerator(1536);
		System.out.print("Big number to encrypt:");
		BigInteger message = new BigInteger("987134698761329847619328746812374983129486132748913268476392817489153287451283547123564756123784651238478123564891235498712356498761239874598172354871324");
		System.out.println(message);
		Long startEncryptionTime =System.nanoTime();
		encryptedMessage = encrypt(message);
		Long encryptTime = (System.nanoTime() - startEncryptionTime);
		System.out.println("Time to encrypt(ns): "+ encryptTime);
		System.out.println("Encrypted message: "+ encryptedMessage);		
		System.out.println("Checking input & n are coprime..."+ (relativelyPrime(encryptedMessage,n)? "Pass":"fail"));
		Long startDecryptionTime =System.nanoTime();
		decryptedMessage = decrypt(encryptedMessage);
		Long decryptTime = (System.nanoTime() - startDecryptionTime);
		System.out.println("Time to decrypt(ns): "+decryptTime);
		System.out.printf("decrypt took %d times longer than encrypt\n", (decryptTime/encryptTime));
		System.out.println("Decrypted message: " + decryptedMessage);
		System.out.println("(Decrypted message == original)--> "+ (decryptedMessage.compareTo(message)==0?"True":"False"));
	}
}
