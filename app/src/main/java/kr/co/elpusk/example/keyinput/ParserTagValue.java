package kr.co.elpusk.example.keyinput;

import java.nio.charset.StandardCharsets;
import java.util.LinkedList;
import java.util.Queue;

interface ParsingConst{
    int CONST_THE_NUMBER_OF_TRACK = 3;
    int CONST_SIZE_DATA_FIELD_LENGTH = 4;
    int CONST_MIN_SIZE_CIPHER_DATA = 3+CONST_SIZE_DATA_FIELD_LENGTH;//e6.e6,e6 and 4 bytes

}

interface ParsingTag{
    int CONST_TAG_E6 = 0xe6;
    int CONST_TAG_C = 0x43;//ASCII 'C'
    int CONST_TAG_FCNT = 0xF0;//flash write count
    int CONST_TAG_KSN = 0xF1;//key serial number
    int CONST_TAG_MPAN = 0xF2;//masked primary account
    int CONST_TAG_CHN = 0xF3;//card holder name
    int CONST_TAG_CED = 0xF4;//card expiration date
    int CONST_TAG_MAC4 = 0xFE;//MAC 4byte
    int CONST_TAG_DISO = 0xFF;//encryption iso track data
}
public class ParserTagValue {

    private enum Mode {
        mNONE,
        mFCNT,
        mKSN,
        mMPAN,
        mCHN,
        mCED,
        mMAC4,
        mISO1,
        mISO2,
        mISO3
    }
    private String m_s_input_with_triple_e6 = "";
    private byte[] m_bin_input_with_triple_e6;
    private int m_n_flash_count = -1;
    private byte[] m_bin_ksn;
    private byte[] m_bin_masked_pan;
    private byte[] m_bin_card_holder_name;
    private byte[] m_bin_card_expiration_date;
    private byte[] m_bin_mac_4bytes;
    private byte[][] m_bins_en_iso;
    private boolean m_b_parsable = false;
    private ParserTagValue(){

    }
    public ParserTagValue(String s_input_without_triple_e6){
        m_s_input_with_triple_e6 = Tools.add_e6_triple(s_input_without_triple_e6);
        m_bin_input_with_triple_e6 = Tools.get_binary_from_hex_string(m_s_input_with_triple_e6);
        m_b_parsable = _parsing();
    }
    public ParserTagValue(byte[] s_input_with_triple_e6) {
        m_bin_input_with_triple_e6 = s_input_with_triple_e6;
        m_s_input_with_triple_e6 = Tools.get_hex_string_from_binary(m_bin_input_with_triple_e6);
        m_b_parsable = _parsing();
    }

    public boolean is_parsable(){
        return m_b_parsable;
    }
    private boolean _parsing()
    {
        boolean b_result = false;
        int n_index = -1;
        int n_offset = 0;
        Mode mode = Mode.mNONE;
        Queue<Byte> item_q = null;

        do{
            if(m_bin_input_with_triple_e6==null){
                continue;
            }
            if(m_bin_input_with_triple_e6.length<ParsingConst.CONST_MIN_SIZE_CIPHER_DATA){
                continue;
            }
            if(Tools.compare_byte(m_bin_input_with_triple_e6[n_offset],ParsingTag.CONST_TAG_E6)!=0){
                continue;
            }
            ++n_offset;
            if(Tools.compare_byte(m_bin_input_with_triple_e6[n_offset],ParsingTag.CONST_TAG_E6)!=0){
                continue;
            }
            ++n_offset;
            if(Tools.compare_byte(m_bin_input_with_triple_e6[n_offset],ParsingTag.CONST_TAG_E6)!=0){
                continue;
            }
            //get length
            ++n_offset;
            byte[] bin_len = new byte[ParsingConst.CONST_SIZE_DATA_FIELD_LENGTH];
            System.arraycopy(m_bin_input_with_triple_e6,n_offset,bin_len,0,bin_len.length);
            int n_len = Tools.get_unsigned_short_from_4bytes_little_endian(bin_len);
            n_offset += 4;

            if(n_len>(m_bin_input_with_triple_e6.length-ParsingConst.CONST_MIN_SIZE_CIPHER_DATA)){
                continue;
            }
            if(Tools.compare_byte(m_bin_input_with_triple_e6[n_offset],ParsingTag.CONST_TAG_C)!=0){
                continue;
            }
            ++n_offset;
            mode = Mode.mNONE;
            b_result = true;//

            while(n_offset<m_bin_input_with_triple_e6.length){
                if(mode == Mode.mNONE){
                    if(Tools.compare_byte(m_bin_input_with_triple_e6[n_offset],ParsingTag.CONST_TAG_FCNT)==0){
                        ++n_offset;
                        mode = Mode.mFCNT;
                        item_q = new LinkedList<>();//reset item buffer
                        continue;
                    }
                    if(Tools.compare_byte(m_bin_input_with_triple_e6[n_offset],ParsingTag.CONST_TAG_KSN)==0){
                        ++n_offset;
                        mode = Mode.mKSN;
                        item_q = new LinkedList<>();//reset item buffer
                        continue;
                    }
                    if(Tools.compare_byte(m_bin_input_with_triple_e6[n_offset],ParsingTag.CONST_TAG_MPAN)==0){
                        ++n_offset;
                        mode = Mode.mMPAN;
                        item_q = new LinkedList<>();//reset item buffer
                        continue;
                    }
                    if(Tools.compare_byte(m_bin_input_with_triple_e6[n_offset],ParsingTag.CONST_TAG_CHN)==0){
                        ++n_offset;
                        mode = Mode.mCHN;
                        item_q = new LinkedList<>();//reset item buffer
                        continue;
                    }
                    if(Tools.compare_byte(m_bin_input_with_triple_e6[n_offset],ParsingTag.CONST_TAG_CED)==0){
                        ++n_offset;
                        mode = Mode.mCED;
                        item_q = new LinkedList<>();//reset item buffer
                        continue;
                    }
                    if(Tools.compare_byte(m_bin_input_with_triple_e6[n_offset],ParsingTag.CONST_TAG_MAC4)==0){
                        ++n_offset;
                        mode = Mode.mMAC4;
                        item_q = new LinkedList<>();//reset item buffer
                        continue;
                    }
                    if(Tools.compare_byte(m_bin_input_with_triple_e6[n_offset],ParsingTag.CONST_TAG_DISO)==0){
                        ++n_offset;
                        ++n_index;
                        if(n_index == 0){
                            mode = Mode.mISO1;
                            item_q = new LinkedList<>();//reset item buffer
                            continue;
                        }
                        if(n_index == 1){
                            mode = Mode.mISO2;
                            item_q = new LinkedList<>();//reset item buffer
                            continue;
                        }
                        if(n_index == 2){
                            mode = Mode.mISO3;
                            item_q = new LinkedList<>();//reset item buffer
                            continue;
                        }
                    }
                    b_result = false;
                    break;//exit while.
                }//the end of NONE mode

                // start NONE mode
                if(is_valied_tag(m_bin_input_with_triple_e6[n_offset])){
                    byte[] b = Tools.get_byte_array_from_queue(item_q);//get value from item buffer
                    if(mode==Mode.mFCNT){
                        if( b == null ){
                            b_result = false;
                            break;//exit while with error
                        }
                        m_n_flash_count = Tools.get_unsigned_int_from_8bytes_little_endian(b);
                        if(m_n_flash_count<0){
                            b_result = false;
                            break;//exit while with error
                        }
                    }
                    else if(mode==Mode.mKSN){
                        if( b == null ){
                            b_result = false;
                            break;//exit while with error
                        }
                        m_bin_ksn = Tools.get_binary_from_hex_string_byte_array(b);
                    }
                    else if(mode==Mode.mMPAN){//mandatory but none when card isn't credit card.
                        m_bin_masked_pan = Tools.get_binary_from_hex_string_byte_array(b);
                    }
                    else if(mode==Mode.mCHN){//option
                        m_bin_card_holder_name = Tools.get_binary_from_hex_string_byte_array(b);
                    }
                    else if(mode==Mode.mCED){//option
                        m_bin_card_expiration_date = Tools.get_binary_from_hex_string_byte_array(b);
                    }
                    else if(mode==Mode.mMAC4){
                        if( b == null ){
                            b_result = false;
                            break;//exit while with error
                        }
                        m_bin_mac_4bytes = Tools.get_binary_from_hex_string_byte_array(b);
                    }
                    else if(mode==Mode.mISO1 || mode==Mode.mISO2 || mode==Mode.mISO3){
                        if( m_bins_en_iso == null ){
                            m_bins_en_iso = new byte[ParsingConst.CONST_THE_NUMBER_OF_TRACK][n_index];
                        }
                        if(b == null ){
                            m_bins_en_iso[n_index] = null;//none track data
                        }
                        else {
                            byte[] cb = Tools.get_binary_from_hex_string_byte_array(b);
                            if(cb != null) {
                                m_bins_en_iso[n_index] = new byte[cb.length];
                                System.arraycopy(cb, 0, m_bins_en_iso[n_index], 0, cb.length);
                            }
                            else {
                                b_result = false;
                                break;//exit while with error
                            }
                        }
                    }
                    else{//invalid mode
                        b_result = false;
                        break;//exit while with error
                    }
                    item_q = new LinkedList<>();//reset item buffer
                    //change mode
                    if(Tools.compare_byte(m_bin_input_with_triple_e6[n_offset],ParsingTag.CONST_TAG_FCNT)==0){
                        ++n_offset;
                        mode = Mode.mFCNT;
                        continue;
                    }
                    if(Tools.compare_byte(m_bin_input_with_triple_e6[n_offset],ParsingTag.CONST_TAG_KSN)==0){
                        ++n_offset;
                        mode = Mode.mKSN;
                        continue;
                    }
                    if(Tools.compare_byte(m_bin_input_with_triple_e6[n_offset],ParsingTag.CONST_TAG_MPAN)==0){
                        ++n_offset;
                        mode = Mode.mMPAN;
                        continue;
                    }
                    if(Tools.compare_byte(m_bin_input_with_triple_e6[n_offset],ParsingTag.CONST_TAG_CHN)==0){
                        ++n_offset;
                        mode = Mode.mCHN;
                        continue;
                    }
                    if(Tools.compare_byte(m_bin_input_with_triple_e6[n_offset],ParsingTag.CONST_TAG_CED)==0){
                        ++n_offset;
                        mode = Mode.mCED;
                        continue;
                    }
                    if(Tools.compare_byte(m_bin_input_with_triple_e6[n_offset],ParsingTag.CONST_TAG_MAC4)==0){
                        ++n_offset;
                        mode = Mode.mMAC4;
                        continue;
                    }
                    if(Tools.compare_byte(m_bin_input_with_triple_e6[n_offset],ParsingTag.CONST_TAG_DISO)==0){
                        ++n_offset;
                        ++n_index;
                        if(n_index == 0){
                            mode = Mode.mISO1;
                            continue;
                        }
                        if(n_index == 1){
                            mode = Mode.mISO2;
                            continue;
                        }
                        if(n_index == 2){
                            mode = Mode.mISO3;
                            continue;
                        }
                    }
                    b_result = false;
                    break;//exit while.
                }

                // getting value of tag
                if(mode == Mode.mNONE){
                    b_result = false;
                    break;//exit while with error
                }
                if( item_q == null ){
                    b_result = false;
                    break;//exit while with error
                }

                item_q.offer(m_bin_input_with_triple_e6[n_offset]);
                ++n_offset;
            }//end while
        }while (false);

        if(b_result && mode == Mode.mMAC4){
            byte[] b = Tools.get_byte_array_from_queue(item_q);//get value from item buffer
            if(b!=null){
                m_bin_mac_4bytes = Tools.get_binary_from_hex_string_byte_array(b);
            }
        }
        return b_result;
    }

    /**
     * check input is valied tag
     * @param c_tag
     * @return true : valied tag. false : unknown tag.
     */
    private boolean is_valied_tag( byte c_tag ){
        boolean b_result = false;
        int n_tag = c_tag&0xFF;
        switch (n_tag){
            case ParsingTag.CONST_TAG_FCNT:
            case ParsingTag.CONST_TAG_KSN:
            case ParsingTag.CONST_TAG_MPAN:
            case ParsingTag.CONST_TAG_CHN:
            case ParsingTag.CONST_TAG_CED:
            case ParsingTag.CONST_TAG_MAC4:
            case ParsingTag.CONST_TAG_DISO:
                b_result = true;
                break;
            default:
                break;
        }//end switch
        return b_result;
    }
    /**
     * get flash memory write count
     * @return int type write count.
     */
    public int get_flash_count(){
        return m_n_flash_count;
    }
    public byte[] get_ksn(){
        return m_bin_ksn;
    }
    public String get_ksn_by_string(){
        String s_out="";

        if(m_bin_ksn!=null){
            s_out = Tools.get_hex_string_from_binary(m_bin_ksn);
        }
        return s_out;
    }
    public byte[] get_mpan(){
        return m_bin_masked_pan;
    }
    public  String get_mpan_by_string(){
        String s_out="";

        if(m_bin_masked_pan!=null){
            s_out = new String(m_bin_masked_pan);
        }
        return s_out;
    }

    public byte[] get_chn(){
        return m_bin_card_holder_name;
    }
    public  String get_chn_by_string(){
        String s_out="";

        if(m_bin_card_holder_name!=null){
            s_out = new String(m_bin_card_holder_name);
        }
        return s_out;
    }
    public byte[] get_ced(){
        return m_bin_card_expiration_date;
    }
    public  String get_ced_by_string(){
        String s_out="";

        if(m_bin_card_expiration_date!=null){
            s_out = new String(m_bin_card_expiration_date);
        }
        return s_out;
    }
    public byte[] get_mac4(){
        return m_bin_mac_4bytes;
    }
    public String get_mac4_by_string(){
        String s_out="";

        if(m_bin_mac_4bytes!=null){
            s_out = Tools.get_hex_string_from_binary(m_bin_mac_4bytes);
        }
        return s_out;
    }

    public byte[] get_track_data(int n_track){
        byte[] bin = null;
        do{
            if(n_track<0 || n_track>=ParsingConst.CONST_THE_NUMBER_OF_TRACK){
                continue;
            }
            if( m_bins_en_iso == null ){
                continue;
            }
            if(m_bins_en_iso.length<=n_track){
                continue;
            }
            if(m_bins_en_iso[n_track] == null){
                continue;
            }
            bin = new byte[m_bins_en_iso[n_track].length];
            System.arraycopy(m_bins_en_iso[n_track],0,bin,0,bin.length);
        }while(false);
        return bin;
    }

    public String get_track_data_by_string(int n_track){
        byte[] bin = get_track_data(n_track);
        if(bin != null){
            return Tools.get_hex_string_from_binary(bin);
        }
        else{
            return "";
        }
    }

}
