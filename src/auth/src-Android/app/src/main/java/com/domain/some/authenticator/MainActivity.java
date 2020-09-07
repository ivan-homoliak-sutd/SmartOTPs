package com.domain.some.authenticator;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.media.MediaScannerConnection;
import android.os.Environment;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    // Identifiers of data sent to the ShowActivity
    public static final String EXTRA_TYPE = "com.domain.some.authenticator.TYPE";
    public static final String EXTRA_SEED = "com.domain.some.authenticator.SEED";
    public static final String EXTRA_SHOW_SEED = "com.domain.some.authenticator.SHOW_SEED";
    //public static final String EXTRA_ROOTHASH = "com.domain.some.authenticator.ROOTHASH";
    //public static final String EXTRA_KEY = "com.domain.some.authenticator.KEY";
    public static final String EXTRA_TOKEN = "com.domain.some.authenticator.TOKEN";
    //public static final String EXTRA_TOKEN_USED = "com.domain.some.authenticator.TOKEN_USED";
    public static final String EXTRA_ID = "com.domain.some.authenticator.ID";
    public static final String EXTRA_LAST_ID = "com.domain.some.authenticator.LAST_ID";
    public static final String EXTRA_PASSWDHASH = "com.domain.some.authenticator.PASSWDHASH";
    public static final String EXTRA_PASSWDSALT = "com.domain.some.authenticator.PASSWDSALT";
    public static final String EXTRA_CFG = "com.domain.some.authenticator.CFG";

    // Identifiers of message sent to the ShowActivity
    // Show activity
    public static final int SHOW_SEED = 0;
    public static final int SHOW_TOKEN = 1;
    public static final int SHOW_CFG = 2;

    // Authenticate activity
    public static final int AUTHENTICATE_PASSWD = 3;

    // GUI Elements (Token Generation)
    private Boolean tokensGenerated;
    private TextView twNotGenerated;
    private TextView twSeed;
    private EditText editSeed;
    private TextView twLeavesNum;
    private Spinner spnLeavesNum;
    private TextView twSubLeavesNum;
    private Spinner spnSubLeavesNum;
    private TextView twChainLen;
    private Spinner spnChainLen;
    private TextView twTokensNum;
    private Button btnGenerate;
    private Button btnGenRndPass;
    private TextView twPassword;
    private EditText editPassword;

    // GUI Elements (Token Retrieve and other)
    private TextView twTokenID;
    private EditText editTokenID;
    private Button btnSubmit;
    private Button btnReset;
    private Button btnShowSeed;
    private Button btnShowCfg;

    private Authenticator authenticator;
    private List<String> dictionary;

    private static final byte AUTHENTICATED_NONE = -1;
    private static final byte AUTHENTICATED_FALSE = 0;
    private static final byte AUTHENTICATED_TRUE = 1;
    private byte authenticated = AUTHENTICATED_NONE;

    private static final String STATE_AUTH = "AUTHENTICATED";
    private static final String STATE_PASSWD = "PASSWD";

    private static final int wordsInMnemonicSentence = 12;

    private void associateItemVars() {
        btnGenerate = findViewById(R.id.btn_generate);
        twNotGenerated = findViewById(R.id.text_not_gen);
        twSeed = findViewById(R.id.text_seed);
        editSeed = findViewById(R.id.edit_seed);
        twLeavesNum = findViewById(R.id.text_leaves_num);
        spnLeavesNum = findViewById(R.id.spn_leaves_num);
        twSubLeavesNum = findViewById(R.id.text_sub_leaves_num);
        spnSubLeavesNum = findViewById(R.id.spn_sub_leaves_num);
        twChainLen = findViewById(R.id.text_chain_len);
        spnChainLen = findViewById(R.id.spn_chain_len);
        twTokensNum = findViewById(R.id.text_tokens_num);
        btnGenRndPass = findViewById(R.id.btn_gen_rnd);
        twPassword = findViewById(R.id.text_main_password);
        editPassword = findViewById(R.id.edit_main_password);

        twTokenID = findViewById(R.id.text_id);
        editTokenID = findViewById(R.id.edit_id);
        btnSubmit = findViewById(R.id.btn_submit);
        btnReset = findViewById(R.id.btn_reset);
        btnShowSeed = findViewById(R.id.btn_show_seed);
        btnShowCfg = findViewById(R.id.btn_show_cfg);
    }

    private void numOfGeneratedTokens() {
        long lN = Long.parseLong(spnLeavesNum.getSelectedItem().toString().replaceAll(",", ""));
        long chL = Long.parseLong(spnChainLen.getSelectedItem().toString().replaceAll(",", ""));
        long tokensNum = lN * chL;

        DecimalFormat formatter = new DecimalFormat("#,###");
        twTokensNum.setText(formatter.format(tokensNum) + " tokens will be generated");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        associateItemVars();

        spnChainLen.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parentView, View selectedItemView, int position, long id) {
                numOfGeneratedTokens();
            }

            @Override
            public void onNothingSelected(AdapterView<?> parentView) {
                //
            }

        });

        spnLeavesNum.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parentView, View selectedItemView, int position, long id) {
                numOfGeneratedTokens();
            }

            @Override
            public void onNothingSelected(AdapterView<?> parentView) {
                //
            }

        });

        authenticator = new Authenticator();

        if (savedInstanceState != null) {
            // Restore value of members from saved state
            authenticated = savedInstanceState.getByte(STATE_AUTH);
            authenticator.setTmpPassword(savedInstanceState.getString(STATE_PASSWD));
        }

        // Load persistent data
        SharedPreferences persistentData = getSharedPreferences("auth_data", Context.MODE_PRIVATE);

        byte[] passwdHash = authenticator.checkIfPasswordExists(persistentData);
        if (passwdHash != null) {
            if (checkIfPasswordRequired(passwdHash))
                return;
        } else
            authenticated = AUTHENTICATED_TRUE;

        if(!isAuthenticated()) {
            twNotGenerated.setText("Authentication not susscessful");
            twNotGenerated.setVisibility(View.VISIBLE);

            return;
        }

        if(!authenticator.checkIfInitialized()) {
            if (authenticator.restoreData(persistentData) != 0)
                tokensGenerated = false;
            else
                tokensGenerated = true;
        } else
            tokensGenerated = true;

        dictionary = loadDictionary();
        if (dictionary == null) {
            twNotGenerated.setText("Unable to load dictionary");
            twNotGenerated.setTextColor(Color.parseColor("#ff0000"));
            twNotGenerated.setVisibility(View.VISIBLE);
            return;
        }

        switchContext(tokensGenerated);
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

    @Override
    public void onSaveInstanceState(Bundle savedInstanceState) {
        // Save auth state
        savedInstanceState.putByte(STATE_AUTH, authenticated);
        savedInstanceState.putString(STATE_PASSWD, authenticator.getTmpPassword());

        super.onSaveInstanceState(savedInstanceState);
    }

    private boolean checkIfPasswordRequired(byte[] passwdHash) {
        if (authenticated == AUTHENTICATED_NONE) {
            Intent intent = new Intent(this, AuthenticateActivity.class);
            intent.putExtra(EXTRA_TYPE, AUTHENTICATE_PASSWD);
            intent.putExtra(EXTRA_PASSWDHASH, passwdHash);
            intent.putExtra(EXTRA_PASSWDSALT, authenticator.getPasswdSalt());

            startActivityForResult(intent, AUTHENTICATE_PASSWD);

            return true;
        }

        return false;
    }

    private boolean isAuthenticated() {
        return authenticated == AUTHENTICATED_TRUE;
    }

    // Switches GUI elements for Token generation phase and token retrieve phase
    private void switchContext(Boolean tokensGenerated) {
        if (tokensGenerated) {

            twNotGenerated.setVisibility(View.INVISIBLE);
            btnGenerate.setVisibility(View.INVISIBLE);
            twSeed.setVisibility(View.INVISIBLE);
            editSeed.setVisibility(View.INVISIBLE);
            btnGenRndPass.setVisibility(View.INVISIBLE);
            twLeavesNum.setVisibility(View.INVISIBLE);
            spnLeavesNum.setVisibility(View.INVISIBLE);
            twSubLeavesNum.setVisibility(View.INVISIBLE);
            spnSubLeavesNum.setVisibility(View.INVISIBLE);
            twChainLen.setVisibility(View.INVISIBLE);
            spnChainLen.setVisibility(View.INVISIBLE);
            twTokensNum.setVisibility(View.INVISIBLE);
            twPassword.setVisibility(View.INVISIBLE);
            editPassword.setVisibility(View.INVISIBLE);

            twTokenID.setVisibility(View.VISIBLE);
            editTokenID.setVisibility(View.VISIBLE);
            btnSubmit.setVisibility(View.VISIBLE);
            btnReset.setVisibility(View.VISIBLE);
            btnShowSeed.setVisibility(View.VISIBLE);
            btnShowCfg.setVisibility(View.VISIBLE);
        } else {
            twNotGenerated.setVisibility(View.VISIBLE);
            btnGenerate.setVisibility(View.VISIBLE);
            twSeed.setVisibility(View.VISIBLE);
            editSeed.setVisibility(View.VISIBLE);
            btnGenRndPass.setVisibility(View.VISIBLE);
            twLeavesNum.setVisibility(View.VISIBLE);
            spnLeavesNum.setVisibility(View.VISIBLE);
            twSubLeavesNum.setVisibility(View.VISIBLE);
            spnSubLeavesNum.setVisibility(View.VISIBLE);
            twChainLen.setVisibility(View.VISIBLE);
            spnChainLen.setVisibility(View.VISIBLE);
            twTokensNum.setVisibility(View.VISIBLE);
            twPassword.setVisibility(View.VISIBLE);
            editPassword.setVisibility(View.VISIBLE);

            twTokenID.setVisibility(View.INVISIBLE);
            editTokenID.setVisibility(View.INVISIBLE);
            btnSubmit.setVisibility(View.INVISIBLE);
            btnReset.setVisibility(View.INVISIBLE);
            btnShowSeed.setVisibility(View.INVISIBLE);
            btnShowCfg.setVisibility(View.INVISIBLE);
        }
    }

    private List<String> loadDictionary() {
        InputStream dictDataIn = getResources().openRawResource(R.raw.english);

        ByteArrayOutputStream dictDataOut = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int length;
        try {
            while ((length = dictDataIn.read(buffer)) != -1) {
                dictDataOut.write(buffer, 0, length);
            }
        } catch (IOException e) {
            return null;
        }

        String dictDataStr = null;
        try {
            dictDataStr = dictDataOut.toString("UTF-8");
        } catch (UnsupportedEncodingException e) {
            return null;
        }

        List<String> dict = Arrays.asList(dictDataStr.split("\n"));
        Utility.setDict(dict);
        return dict;
    }

    private void handleAuthGenError(int err) {
        if (err == Authenticator.errNoSuchAlgorithm) {
            editSeed.setText("");
            editSeed.setHint("Provided Alg not supported");
        } else if (err == Authenticator.errInvalidMnemonicSencence) {
            editSeed.setText("");
            editSeed.setHint("Provided Seed incorrect");
        } else if (err == Authenticator.errInvalidPassword) {
            editPassword.setText("");
            editPassword.setHint("Password cannot be used");
        }
    }

    public void generateSecretTokens(View view) {
        int numOfLeaves;
        int numOfSubLeaves;
        int chainLen;
        String passphrase;
        String password;

        passphrase = editSeed.getText().toString();
        if (passphrase.equals("")) {
            editSeed.setHint("No seed entered");
            return;
        }

        if (passphrase.split(" ").length < wordsInMnemonicSentence || Utility.mnemonicSentenceToByteArray(passphrase, dictionary) == null) {
            editSeed.setText("");
            editSeed.setHint("Seed incorrect");
            return;
        }

        password = editPassword.getText().toString();
        if (password.equals("")) {
            editPassword.setHint("No password entered");
            return;
        }

        numOfLeaves = Integer.parseInt(spnLeavesNum.getSelectedItem().toString().replaceAll(",", ""));
        numOfSubLeaves = Integer.parseInt(spnSubLeavesNum.getSelectedItem().toString().replaceAll(",", ""));
        chainLen = Integer.parseInt(spnChainLen.getSelectedItem().toString().replaceAll(",", ""));

        if (numOfSubLeaves > numOfLeaves) {
            twTokensNum.setText("Err: Sub-tree size > tree size");
            return;
        }

        int res = authenticator.initAuthenticator(passphrase, password, numOfLeaves, numOfSubLeaves, chainLen);
        if (res == Authenticator.errOK) {
            tokensGenerated = true;
            switchContext(tokensGenerated);
        } else {
            handleAuthGenError(res);
            return;
        }

        SharedPreferences persistentData = getSharedPreferences("auth_data", Context.MODE_PRIVATE);
        authenticator.storeData(persistentData);

        Intent intent = new Intent(this, ShowActivity.class);
        intent.putExtra(EXTRA_TYPE, SHOW_SEED);
        intent.putExtra(EXTRA_SEED, authenticator.getSeed());

        startActivityForResult(intent, SHOW_SEED);
    }

    public void generateRandomSeed(View view) {
        String passphrase = authenticator.generateRandomSeed(dictionary);
        editSeed.setText(passphrase);
    }

    public void getSecretToken(View view) {
        long tokenID;
        String strToken;

        strToken = editTokenID.getText().toString();
        if (strToken.equals("")) {
            editTokenID.setHint("No ID entered");
            return;
        }

        // Check boundaries
        tokenID = Long.parseLong(strToken.replaceAll(",", ""));
        tokenID -= 1;
        if (tokenID <= (authenticator.getLastID() - authenticator.getNumOfTokens()) || tokenID > authenticator.getLastID()) {
            editTokenID.setText("");
            editTokenID.setHint("ID is incorrect");
            return;
        }


        strToken = Utility.getMnemonicSentence(authenticator.getSecretToken(tokenID, dictionary), dictionary);
        editTokenID.setText("");
        editTokenID.setHint("Enter ID");

        Intent intent = new Intent(this, ShowActivity.class);
        intent.putExtra(EXTRA_TYPE, SHOW_TOKEN);
        intent.putExtra(EXTRA_TOKEN, strToken);
        intent.putExtra(EXTRA_ID, tokenID);

        if (tokenID == authenticator.getLastID()) {
            intent.putExtra(EXTRA_LAST_ID, true);
            intent.putExtra(EXTRA_SEED, authenticator.getSeed());
        }

        startActivityForResult(intent, SHOW_TOKEN);
    }

    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (requestCode == SHOW_TOKEN) {
            if (resultCode == RESULT_OK) {
                long usedTokenID = data.getLongExtra(ShowActivity.EXTRA_RET_ID, -1);
                if (usedTokenID != -1) {
                    if (usedTokenID == authenticator.getLastID()) {
                        SharedPreferences persistentData = getSharedPreferences("auth_data", Context.MODE_PRIVATE);
                        authenticator.incTreeNum(persistentData);
                    }
                }

                return;
            } else if (resultCode == RESULT_CANCELED) {
                // TODO: Probably no need to do anything
                return;
            }
        } else if (requestCode == SHOW_SEED) {
            // TODO: Eventually do something
            return;
        } else if (requestCode == SHOW_CFG) {
            // TODO: Eventually do something
            return;
        } else if (requestCode == AUTHENTICATE_PASSWD) {
            if (resultCode == RESULT_OK) {
                authenticated = AUTHENTICATED_TRUE;
                authenticator.setTmpPassword(data.getStringExtra(AuthenticateActivity.EXTRA_RET_PASSWD));
            } else
                authenticated = AUTHENTICATED_FALSE;

            if(!isAuthenticated()) {
                twNotGenerated.setText("Authentication not susscessful");
                twNotGenerated.setVisibility(View.VISIBLE);
                btnGenerate.setVisibility(View.INVISIBLE);
                twSeed.setVisibility(View.INVISIBLE);
                editSeed.setVisibility(View.INVISIBLE);
                btnGenRndPass.setVisibility(View.INVISIBLE);
                twLeavesNum.setVisibility(View.INVISIBLE);
                spnLeavesNum.setVisibility(View.INVISIBLE);
                twSubLeavesNum.setVisibility(View.INVISIBLE);
                spnSubLeavesNum.setVisibility(View.INVISIBLE);
                twChainLen.setVisibility(View.INVISIBLE);
                spnChainLen.setVisibility(View.INVISIBLE);
                twTokensNum.setVisibility(View.INVISIBLE);
                twPassword.setVisibility(View.INVISIBLE);
                editPassword.setVisibility(View.INVISIBLE);
                twTokenID.setVisibility(View.INVISIBLE);
                editTokenID.setVisibility(View.INVISIBLE);
                btnSubmit.setVisibility(View.INVISIBLE);
                btnReset.setVisibility(View.INVISIBLE);
                btnShowSeed.setVisibility(View.INVISIBLE);
                btnShowCfg.setVisibility(View.INVISIBLE);

                return;
            }

            if(!authenticator.checkIfInitialized()) {

                // Load persistent data
                SharedPreferences persistentData = getSharedPreferences("auth_data", Context.MODE_PRIVATE);

                tokensGenerated = authenticator.restoreData(persistentData) == 0;
            } else
                tokensGenerated = true;

            dictionary = loadDictionary();

            switchContext(tokensGenerated);
        }
    }

    @Override
    public void recreate()
    {
        super.recreate();
    }

    public void resetAuthenticator(View view) {
        SharedPreferences persistentData = getSharedPreferences("auth_data", Context.MODE_PRIVATE);
        editSeed.setText("");
        editPassword.setText("");
        spnLeavesNum.setSelection(0);
        spnSubLeavesNum.setSelection(0);
        spnChainLen.setSelection(0);
        authenticator.reset(persistentData);
        recreate();
    }

    public void showSeed(View view) {
        Intent intent = new Intent(this, ShowActivity.class);
        intent.putExtra(EXTRA_TYPE, SHOW_SEED);
        intent.putExtra(EXTRA_SEED, authenticator.getSeed());
        intent.putExtra(EXTRA_SHOW_SEED, 1);

        startActivityForResult(intent, SHOW_SEED);
    }

    public void showCfg(View view) {
        DecimalFormat formatter = new DecimalFormat("#,###");
        String cfgStr = new String("Main Tree ID: " + formatter.format(authenticator.getTreeNum()) + "\n"
        + "Number of leaves in parent tree: " + formatter.format(authenticator.getNumOfLeaves()) + "\n"
        + "Number of leaves in sub-tree: " + formatter.format(authenticator.getNumOfSubLeaves()) + "\n"
        + "Chain length: " + formatter.format(authenticator.getChainLen()));

        Intent intent = new Intent(this, ShowActivity.class);
        intent.putExtra(EXTRA_TYPE, SHOW_CFG);
        intent.putExtra(EXTRA_CFG, cfgStr);

        startActivityForResult(intent, SHOW_SEED);
    }
}

