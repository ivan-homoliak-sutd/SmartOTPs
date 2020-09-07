package com.domain.some.authenticator;

import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class AuthenticateActivity extends AppCompatActivity {

    public static final String EXTRA_RET_PASSWD = "com.domain.some.authenticator.extra.RET_PASSWD";

    private static final int maxAttempts = 3;

    private int attempts = 0;
    private byte[] passwdHash;
    private byte[] passwdSalt;

    private EditText editPasswd;
    private Button btnPasswd;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_authenticate);

        editPasswd = findViewById(R.id.edit_passwd);
        btnPasswd = findViewById(R.id.btn_passwd);

        Intent intent = getIntent();
        passwdHash = intent.getByteArrayExtra(MainActivity.EXTRA_PASSWDHASH);
        passwdSalt = intent.getByteArrayExtra(MainActivity.EXTRA_PASSWDSALT);
    }

    public void minimizeApp() {
        Intent startMain = new Intent(Intent.ACTION_MAIN);
        startMain.addCategory(Intent.CATEGORY_HOME);
        startMain.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(startMain);
    }

    @Override
    public void onBackPressed() {
        boolean shouldAllowBack = true;
        if (!shouldAllowBack) {
            return;
        } else {
            minimizeApp();
        }
    }

    private boolean checkIfPasswdMatch(byte[] passwdHash) {
        String providedPasswd = editPasswd.getText().toString();

        byte[] hash = Authenticator.sha256DigestSalted(providedPasswd.getBytes(), passwdSalt);

        return Arrays.equals(hash, passwdHash);
    }

    public void passwdSubmitted(View view) {

        boolean passwdMatch = checkIfPasswdMatch(passwdHash);

        if (!passwdMatch) {
            editPasswd.setText("");
            editPasswd.setHint("Password incorrect");
            attempts++;
        }

        if (passwdMatch || attempts == maxAttempts) {

            Intent returnIntent = new Intent();

            if (passwdMatch) {
                returnIntent.putExtra(EXTRA_RET_PASSWD, editPasswd.getText().toString());
                setResult(RESULT_OK, returnIntent);
            } else
                setResult(RESULT_CANCELED, returnIntent);

            finish();
        }
    }
}
