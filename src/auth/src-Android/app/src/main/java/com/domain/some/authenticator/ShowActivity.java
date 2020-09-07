package com.domain.some.authenticator;

import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;

import com.google.zxing.WriterException;

import java.text.DecimalFormat;

public class ShowActivity extends AppCompatActivity {

    public static final String EXTRA_RET_ID = "com.domain.some.authenticator.extra.RET_ID";

    private TextView twShowValue;
    private TextView twSeedLabel;
    private TextView twSeedValue;
    private TextView twClient;
    private Button btnDone;
    private Button btnCancel;
    private ImageView ivQRCode;

    private long tmpID = -1;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_show);

        twShowValue = findViewById(R.id.text_show_value);
        twSeedLabel = findViewById(R.id.text_seed_label);
        twSeedValue = findViewById(R.id.text_seed_value);
        twClient = findViewById(R.id.text_client);
        btnDone = findViewById(R.id.btn_done);
        btnCancel = findViewById(R.id.btn_cancel);
        ivQRCode = findViewById(R.id.iv_qr_code);

        Intent intent = getIntent();
        int msg_type = intent.getIntExtra(MainActivity.EXTRA_TYPE, -1);

        if (msg_type == MainActivity.SHOW_TOKEN) {
            switchContext(MainActivity.SHOW_TOKEN);

            String secretToken = intent.getStringExtra(MainActivity.EXTRA_TOKEN);
            long secretTokenID = intent.getLongExtra(MainActivity.EXTRA_ID, -1);
            tmpID = secretTokenID;
            secretTokenID += 1;

            DecimalFormat formatter = new DecimalFormat("#,###");
            String textMsg = new String("OTP " + formatter.format(secretTokenID));
            setTitle(textMsg);
            twShowValue.setText(secretToken);

            try {
                byte[] mnemByte = Utility.mnemonicSentenceToByteArray(secretToken, Utility.getDict());
                QrCode qr0 = QrCode.encodeBinary(mnemByte, QrCode.Ecc.LOW);
                Bitmap bitmap = qr0.toImage(21, 4);
                ivQRCode.setImageBitmap(bitmap);
                ivQRCode.setVisibility(View.VISIBLE);
            } catch (Exception e) {
                e.printStackTrace();
            }
            /*
            boolean lastID = intent.getBooleanExtra(MainActivity.EXTRA_LAST_ID, false);
            if (lastID) {
                String seed = intent.getStringExtra(MainActivity.EXTRA_SEED);
                twSeedValue.setText(seed);
                twSeedLabel.setVisibility(View.VISIBLE);
                twSeedValue.setVisibility(View.VISIBLE);
            }
            */
        }
        else if (msg_type == MainActivity.SHOW_SEED) {
            switchContext(MainActivity.SHOW_SEED);
            setTitle("Seed");

            int justShow = intent.getIntExtra(MainActivity.EXTRA_SHOW_SEED, -1);
            if (justShow != -1)
                twClient.setText("");

            String passphrase = intent.getStringExtra(MainActivity.EXTRA_SEED);
            twShowValue.setText(passphrase);

            try {

                byte[] mnemByte = Utility.mnemonicSentenceToByteArray(passphrase, Utility.getDict());
                QrCode qr0 = QrCode.encodeBinary(mnemByte, QrCode.Ecc.LOW);
                Bitmap bitmap = qr0.toImage(21, 4);
                ivQRCode.setImageBitmap(bitmap);
                ivQRCode.setVisibility(View.VISIBLE);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        else if (msg_type == MainActivity.SHOW_CFG) {
            switchContext(MainActivity.SHOW_CFG);
            setTitle("Configuration");

            String cfgStr = intent.getStringExtra(MainActivity.EXTRA_CFG);
            if (cfgStr == null)
                twShowValue.setText("");
            else
                twShowValue.setText(cfgStr);
        }

    }

    private void switchContext(int type) {
        if (type == MainActivity.SHOW_TOKEN) {
            btnCancel.setVisibility(View.VISIBLE);
        }
        else if (type == MainActivity.SHOW_SEED) {
            btnCancel.setVisibility(View.INVISIBLE);
        }
        else if (type == MainActivity.SHOW_CFG) {
            btnCancel.setVisibility(View.INVISIBLE);
            twClient.setVisibility(View.INVISIBLE);
        }
    }

    public void returnDoneToMain(View view) {
        Intent returnIntent = new Intent();

        if (tmpID != -1)
            returnIntent.putExtra(EXTRA_RET_ID, tmpID);

        setResult(RESULT_OK, returnIntent);
        finish();
    }

    public void returnCancelToMain(View view) {
        Intent returnIntent = new Intent();

        setResult(RESULT_CANCELED, returnIntent);
        finish();
    }
}

