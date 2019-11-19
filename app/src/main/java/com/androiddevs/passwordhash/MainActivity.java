package com.androiddevs.passwordhash;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MainActivity";

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        final EditText etPassword = findViewById(R.id.etPassword);
        Button btnCreateHash = findViewById(R.id.btnCreateHash);
        final TextView tvHash = findViewById(R.id.tvHash);

        // the more iterations the longer it will take to generate the hash
        // so also the attacker needs more time to try out hashes
        final int NUMBER_OF_ITERATIONS = 5000;

        btnCreateHash.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                try {
                    String password = etPassword.getText().toString();
                    final String hashedPW = generatePasswordHash(password, NUMBER_OF_ITERATIONS);
                    tvHash.setText("Save this String in your database:\n\n" + hashedPW);

                    if (validatePassword(password, hashedPW, NUMBER_OF_ITERATIONS)) {
                        Toast.makeText(MainActivity.this,
                                "Correct Password!", Toast.LENGTH_SHORT).show();
                    } else {
                        Toast.makeText(MainActivity.this,
                                "Invalid Password!", Toast.LENGTH_SHORT).show();
                    }
                } catch (Exception e) {
                    Log.e(TAG, "onCreate: ", e);
                }
            }
        });
    }

    private String generatePasswordHash(String password, int iterations)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        int keyLength = 512;
        char[] charArray = password.toCharArray();

        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        // a salt is a random sequence of bytes that is attached to our
        // password to make the hash more secure
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        PBEKeySpec pbeks = new PBEKeySpec(charArray, salt, iterations, keyLength);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hash = skf.generateSecret(pbeks).getEncoded();

        return convertToHex(salt) + "-" + convertToHex(hash);
    }

    // this function converts our hashedBytes to a string in hex format
    private String convertToHex(byte[] bytes) {
        BigInteger integer = new BigInteger(1, bytes);
        String hex = integer.toString(16);
        int paddingLength = (bytes.length * 2) - hex.length();

        return paddingLength > 0 ? String.format("%0" + paddingLength + "d", 0) + hex : hex;
    }

    private boolean validatePassword(String password, String hashedPassword, int iterations)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        String[] parts = hashedPassword.split("-");
        byte[] salt = convertFromHex(parts[0]);
        byte[] hash = convertFromHex(parts[1]);

        PBEKeySpec pbeks = new PBEKeySpec(password.toCharArray(), salt, iterations, hash.length * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] testHash = skf.generateSecret(pbeks).getEncoded();

        int diff = hash.length ^ testHash.length;
        for (int i = 0; i < hash.length && i < testHash.length; i++) {
            diff |= hash[i] ^ testHash[i];
        }
        return diff == 0;
    }

    // this function takes the string in hex format and converts it to bytes
    private byte[] convertFromHex(String hexString) {
        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hexString.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }
}
