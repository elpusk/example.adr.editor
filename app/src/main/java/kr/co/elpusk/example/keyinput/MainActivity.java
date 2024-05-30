package kr.co.elpusk.example.keyinput;

import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    private EditText editText;
    private Button button, bt_clear;
    private TextView textView;

    private ParserTagValue m_tag_value = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // EditText, Button, TextView 초기화
        editText = findViewById(R.id.editText);
        button = findViewById(R.id.button);
        textView = findViewById(R.id.textView);
        bt_clear = findViewById(R.id.clear);

        // EditText에 포커스 이벤트 리스너 추가
        editText.setOnFocusChangeListener(new View.OnFocusChangeListener() {
            @Override
            public void onFocusChange(View v, boolean hasFocus) {
                if (hasFocus) {
                    // 가상 키보드 숨기기
                    InputMethodManager imm = (InputMethodManager) getSystemService(INPUT_METHOD_SERVICE);
                    imm.hideSoftInputFromWindow(v.getWindowToken(), 0);
                }
            }

        });
        editText.addTextChangedListener(new TextWatcher() {
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
                textView.setText("CNT: " + charCount); // TextView에 표시
            }
        });
        bt_clear.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                editText.getText().clear();
            }
        });
        // 버튼 클릭 리스너 설정
        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // EditText에서 텍스트 가져오기
                String inputText = editText.getText().toString();
                m_tag_value = new ParserTagValue(inputText);
                if(m_tag_value.is_parsable() ){
                    StringBuilder s_info = new StringBuilder();
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
                        s_info.append(m_tag_value.get_track_data_by_string(i));
                        s_info.append("\n");
                    }
                    textView.setText(s_info);
                }
                else {
                    // TextView에 텍스트 설정하기
                    textView.setText("Parssing error");
                }
            }
        });
    }
}