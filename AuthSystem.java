import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;


/* Author: Craig Murphy
 * 28/10/2025
 * Secure Application Programming
 * 
 * Preventing common security flaws such as:
 * 
 * Plain text password storage 
 * Timing attacks 
 * User enumeration
 * Brute force attacks
 * Weak session hanlding
 * 
 */

 public class AuthSystem{

    //In-memory user store and session store
    private final Map<String, User> users = new ConcurrentHashMap<>();
    private final Map<String , Session> sessions = new ConcurrentHashMap<>();

    //parameters for password hashing and session management

    private static final int SALT_LENGTH = 16;                      // 16 bytes = 128 bits salt
    private static final int HASH_ITERATIONS = 200_000;           // high iterations for PBKDF2
    private static final int HASH_KEY_LENGTH = 256;                  // 256 bits key length
    private static final int MAX_LOGIN_ATTEMPTS = 5;               // Max login attempts before lockout
    private static final long LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes
    private static final long SESSION_EXPIRY_MS = 30 * 60 * 1000; // 30 minutes

    //secure random generator for salts and session tokens
    private final SecureRandom secureRandom = new SecureRandom();


    //user record in the system 
    //passwords aren't stored in plain text but as salted hashes

    private static class User{
        String username;        // Depending on IDE being used, "username" highlighted because of file name difference, not a syntax issue 
        byte[] salt;                    // unique salt per user
        byte[] passwordHash;            // hashed password
        int failedLoginAttempts = 0;    // count of failed login attempts
        long lockoutEndTime = 0;

        User(String username, byte[] salt, byte[] passwordHash){
            this.username = username;
            this.salt = salt;
            this.passwordHash = passwordHash;
        }

    }



    //session record
    private static class Session{
        String sessionToken;       // unique session token   // Depending on IDE being used, "username" highlighted because of file name difference, not a syntax issue  
        long expiryTime;        // session expiry time

        Session(String sessionToken, long expiryTime){
            this.sessionToken = sessionToken;
            this.expiryTime = expiryTime;
        }
    }

    // register a new user
    // returns fasle if username already exists
    public boolean register(String username, String password){
        if (username == null || password == null) 
        return false;        // input validation

        if (users.containsKey(username)){
            return false;           // user already exists
        }

        // generate salt
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);

        // a string password hash using PBKDF2
        byte[] hash = hashPassword(password.toCharArray(), salt);

        // storing user
        users.put(username, new User(username, salt, hash));
        return true;
    }

    // login user
    public String login(String username, String password){
        long startTime = System.nanoTime();         // response time measurement
        User user = users.get(username);

        // a dummy salt for fake validation if user not found
        byte[] dummySalt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(dummySalt);
        byte[] dummyHash = hashPassword("PasswordIsAFake".toCharArray(), dummySalt);

        boolean loginSuccessful = false;

        if (user != null){
            // lockout check
            if (System.currentTimeMillis() < user.lockoutEndTime){
                delayResponse(startTime);
                return null;
            }

            // hash the provided password with the stored salt
            byte[] attemptHash = hashPassword(password.toCharArray(), user.salt);

            if(MessageDigest.isEqual(attemptHash, user.passwordHash)){

                user.failedLoginAttempts = 0; //reset failed attempts
                loginSuccessful = true;
            } else {
                user.failedLoginAttempts++;
                if(user.failedLoginAttempts >= MAX_LOGIN_ATTEMPTS){
                    user.lockoutEndTime = System.currentTimeMillis() + LOCKOUT_DURATION_MS;
                }
            }

        } else {
            MessageDigest.isEqual(dummyHash, dummyHash); //fake hash comparison
        }

        delayResponse(startTime); // ensure constant response time

        // if login successful, generate session token
        if (loginSuccessful && user != null){
            String token = generateSessionToken();
            sessions.put(token, new Session(token, System.currentTimeMillis() + SESSION_EXPIRY_MS));
            return token;
        }
        // login failed
        return null;
    }

        // checking if session token is valid or expired
        public boolean isSessionValid(String token){
            if (token == null)
            return false;
            Session session = sessions.get(token);

            if (session == null)
            return false;

            if(System.currentTimeMillis() > session.expiryTime){
                sessions.remove(token);
                return false;
            }
            return true;
        }

        // generating a cryptograpically string session token
        private String generateSessionToken(){
            byte[] randomBytes = new byte[32];
            secureRandom.nextBytes(randomBytes);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        }

        // derives a PBKDF2WithHmacSHA256 hash from the provided password and salt
        private byte[] hashPassword(char[] password, byte[] salt) {
            try {
                PBEKeySpec spec = new PBEKeySpec(password, salt, HASH_ITERATIONS,HASH_KEY_LENGTH);
                SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                return skf.generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new RuntimeException("Secure Hashing has Failed", e);
            }
        }
        // adding a delay to all login responses 
        // preventing attackers from measuring time differences 
        private void delayResponse(long startTime){
            long elapsed = System.nanoTime() - startTime;
            long target = 50_000_000L; 

            if(elapsed < target){
                try{
                    Thread.sleep((target - elapsed) /1_000_000L);
                }catch (InterruptedException ignored){
                    Thread.currentThread().interrupt();
                }
            }
        }
    }


 