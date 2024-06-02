package kr.co.elpusk.example.keyinput;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

interface ConstTest{
    String CONST_IV = "0000000000000000";//unchangeable initial vector of CBC mode.
    String CONST_TEST_KEYBOARD_RSP = "4634303143F03036303030303030F14646464639383736353433323130453030303035F2F3F4FF344333424131463730383238373534373734344141333431373142364432443939323541443135303835383631433845394242373436303131464244393342334144344436333536303535463032354444453543334630443632393144323736424433333046393241323146463746344242464134443035374235453233444241373036373239373236453941463831343243434434444241304644363339394142FF32353342413146373038323837353437373441463542373639314439323238304131344441373031323538344439443241443833463631383343354630324545353436383230454544323132383546333033FF363833424131463730383238373534373734414635423736393144393232383041313444413730313235383444394432414438334636313833433546303245453534334346344633383337343531313546383734343035393934463042303734423235323438464345314334423232334538464444303832354539333331424236363041353338324634433746334534303736373042393536383739373539394236373844384335444439394334384336453439323341334343443142394646463944444135463642444244383735363734FE4230453137373031";
    String[] CONST_TEST_IPEK ={
            "6AC292FAA1315B4D858AB3A3D7D5933A",
            "00000000000000000000000000000000"
    };
}
public class MainActivity extends AppCompatActivity {

    private EditText m_editTextInput;
    private Button m_buttonRun, m_buttonTestSet, m_buttonClear;
    private TextView m_textViewResult, m_textViewHeader;

    private ExecutorService executorService;
    private Handler mainHandler;
    private ParserTagValue m_tag_value = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // EditText, Button, TextView 초기화
        m_textViewHeader = findViewById(R.id.headerTextView);

        m_buttonClear = findViewById(R.id.clearButton);
        m_buttonTestSet = findViewById(R.id.testSetButton);
        m_buttonRun = findViewById(R.id.runButton);

        m_editTextInput = findViewById(R.id.inputEditText);
        m_textViewResult = findViewById(R.id.resultTextView);

        m_textViewHeader.setText("lpu237 description test");

        // EditText에 포커스 이벤트 리스너 추가
        m_editTextInput.setOnFocusChangeListener(new View.OnFocusChangeListener() {
            @Override
            public void onFocusChange(View v, boolean hasFocus) {
                if (hasFocus) {
                    // 가상 키보드 숨기기
                    InputMethodManager imm = (InputMethodManager) getSystemService(INPUT_METHOD_SERVICE);
                    imm.hideSoftInputFromWindow(v.getWindowToken(), 0);
                }
            }

        });
        m_editTextInput.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                // 입력하기 전
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                // 입력 중
            }

            @Override
            public void afterTextChanged(Editable s) {
                // 입력 후
                int charCount = s.length(); // 입력된 문자 수 계산
                m_textViewResult.setText("CNT: " + charCount); // TextView에 표시
            }
        });

        m_buttonClear.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                m_editTextInput.getText().clear();
                m_textViewResult.setText("");
            }
        });

        m_buttonTestSet.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                m_editTextInput.getText().clear();
                m_editTextInput.setText(ConstTest.CONST_TEST_KEYBOARD_RSP);

            }
        });
        // 버튼 클릭 리스너 설정
        m_buttonRun.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // EditText에서 텍스트 가져오기
                String inputText = m_editTextInput.getText().toString();

                m_textViewResult.setText("Please waiting calculating");

                executorService = Executors.newSingleThreadExecutor();
                mainHandler = new Handler(Looper.getMainLooper());

                startLongRunningTask(inputText);

            }
        });
    }

    private void startLongRunningTask(String s_input) {
        executorService.execute(new Runnable() {
            @Override
            public void run() {
                final String result = performLongRunningCalculation(s_input);

                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        m_textViewResult.setText(result);
                    }
                });
            }
        });
    }

    private String performLongRunningCalculation(String s_input) {
        m_tag_value = new ParserTagValue(s_input);//parsing
        String s_info = _getParsedInfo();

        do{
            if(!m_tag_value.is_parsable()) {
                continue;
            }
            String[] s_ipek = ConstTest.CONST_TEST_IPEK;

            byte[][] ipek = new byte [2][16];
            System.arraycopy(Tools.get_binary_from_hex_string(s_ipek[0]),0,ipek[0],0,ipek[0].length);
            System.arraycopy(Tools.get_binary_from_hex_string(s_ipek[1]),0,ipek[1],0,ipek[1].length);

            DukptTdes dukpt = new DukptTdes(m_tag_value.get_ksn(),ipek);
            if(!dukpt.is_setup_ok()){
                s_info = s_info + "\n dukpt error.";
                continue;
            }

            byte[] raw_data_except_mac = m_tag_value.get_raw_data_except_mac(true,true);
            byte[] mac4 = dukpt.generate_mac_4bytes(raw_data_except_mac);//calculate MAC4
            s_info = s_info + "\n calculate MAC4 = " + Tools.get_hex_string_from_binary(mac4);

            // compare the calculated MAC4 and the given MAC4
            if(!Tools.is_equal_bytes(mac4,m_tag_value.get_mac4())) {
                s_info = s_info + "\n Mismatch MAC! the given message may be sent from unauthenticated device.";
                continue;
            }

            // decryption card data.
            String s_iv = ConstTest.CONST_IV;
            byte[] iv = Tools.get_binary_from_hex_string(s_iv);
            byte[] en_key = dukpt.get_encrypt_key();

            for (int i = 0; i < 3; i++) {
                byte[] en_iso = m_tag_value.get_encrypted_track_data(i);//get plaintext length + encrypted track data.
                if (en_iso.length <= 0) {
                    s_info = s_info + "\n ISO" + String.valueOf(i + 1) + " = NONE";
                    continue;
                }

                int n_iso = en_iso[0];//get signed char type. the size of decrypted iso track data
                if (n_iso <= 0) {
                    s_info = s_info + "\n ISO" + String.valueOf(i + 1) + " = NONE";
                }

                byte[] en_iso_except_len = new byte[en_iso.length - 1];
                System.arraycopy(en_iso, 1, en_iso_except_len, 0, en_iso_except_len.length);

                byte[] iso = DukptTdes.decrypt3DESCBC(en_key, iv, en_iso_except_len);

                //remove padding data from decrypted data.
                byte[] raw_iso = new byte[n_iso];
                System.arraycopy(iso, 0, raw_iso, 0, raw_iso.length);

                String s_iso = new String(raw_iso);
                s_info = s_info + "\n ISO" + String.valueOf(i + 1) + s_iso;
            }//end for

        }while(false);
        return s_info;
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executorService.shutdown();
    }
    private String _getParsedInfo(){
        StringBuilder s_info = new StringBuilder();

        if(m_tag_value.is_parsable() ){
            s_info.append("KSN : ");
            s_info.append(m_tag_value.get_ksn_by_string());
            s_info.append("\n");

            s_info.append("Masked PAN : ");
            s_info.append(m_tag_value.get_mpan_by_string());
            s_info.append("\n");

            s_info.append("Card Holder Name : ");
            s_info.append(m_tag_value.get_chn_by_string());
            s_info.append("\n");

            s_info.append("Card Expiration Date : ");
            s_info.append(m_tag_value.get_ced_by_string());
            s_info.append("\n");

            s_info.append("Message Authentication Code 4bytes : ");
            s_info.append(m_tag_value.get_mac4_by_string());
            s_info.append("\n");
            for(int i=0; i<3; i++) {
                s_info.append("Encrypted ISO");
                s_info.append(i+1);
                s_info.append(" : ");
                s_info.append(m_tag_value.get_encrypted_track_data_by_string(i));
                s_info.append("\n");
            }
        }
        else {
            // TextView에 텍스트 설정하기
            s_info.append("Parssing error");
        }
        return s_info.toString();
    }
}