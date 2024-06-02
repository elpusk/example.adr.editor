package kr.co.elpusk.example.keyinput;

import java.nio.charset.StandardCharsets;
import java.util.LinkedList;
import java.util.Queue;

/**
 * definition of const Paring.
 */
interface ParsingConst{
    int CONST_THE_NUMBER_OF_TRACK = 3;//the number of ISO tracks
    int CONST_SIZE_DATA_FIELD_LENGTH = 4;//the length of data size field

    /**
     * e6.e6,e6 and 4 bytes. triple e6 is only usb keyboard & uart interface.
     */
    int CONST_MIN_SIZE_CIPHER_DATA = 3+CONST_SIZE_DATA_FIELD_LENGTH;

}

/**
 * the definition of Tag
 */
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

/**
 * Parsing the response of lpu237 encryption mode.
 * you can use this class for usb-keyboard interface, uart-interface and usb-vendor-hid interface.
 */
public class ParserTagValue {

    /**
     * internal parsing status.
     */
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
    private byte[] m_bin_input_with_triple_e6 = new byte[0];
    private int m_n_flash_count = -1;
    private byte[] m_bin_flash_count = new byte[0];
    private byte[] m_raw_flash_count = new byte[0];
    private byte[] m_bin_ksn = new byte[0];
    private byte[] m_raw_ksn = new byte[0];
    private byte[] m_bin_masked_pan = new byte[0];
    private byte[] m_raw_masked_pan = new byte[0];
    private byte[] m_bin_card_holder_name = new byte[0];
    private byte[] m_raw_card_holder_name = new byte[0];
    private byte[] m_bin_card_expiration_date = new byte[0];
    private byte[] m_raw_card_expiration_date = new byte[0];
    private byte[] m_bin_mac_4bytes = new byte[0];
    private byte[] m_raw_mac_4bytes = new byte[0];
    private byte[][] m_bins_en_iso = new byte[ParsingConst.CONST_THE_NUMBER_OF_TRACK][0];
    private byte[][] m_raw_en_iso = new byte[ParsingConst.CONST_THE_NUMBER_OF_TRACK][0];
    private boolean m_b_parsable = false;

    /**
     * the default constructor is disabled. !
     */
    private ParserTagValue(){

    }

    /**
     * constructor for usb-keyboard interface & uart-interface in encryption mode.
     * @param s_input_without_triple_e6 : response of  usb-keyboard interface & uart-interface.
     */
    public ParserTagValue(String s_input_without_triple_e6){
        m_s_input_with_triple_e6 = Tools.add_e6_triple(s_input_without_triple_e6);
        m_bin_input_with_triple_e6 = Tools.get_binary_from_hex_string(m_s_input_with_triple_e6);
        m_b_parsable = _parsing();
    }

    /**
     * constructor for usb-vendor hid interface in encryption mode.
     * @param s_input_with_triple_e6
     */
    public ParserTagValue(byte[] s_input_with_triple_e6) {
        m_bin_input_with_triple_e6 = s_input_with_triple_e6;
        m_s_input_with_triple_e6 = Tools.get_hex_string_from_binary(m_bin_input_with_triple_e6);
        m_b_parsable = _parsing();
    }

    /**
     * get parsing result
     * @return true : success, false : error
     */
    public boolean is_parsable(){
        return m_b_parsable;
    }

    /**
     * parsing encrypted response.
     * @return true : success, false : error
     */
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
                        m_bin_flash_count = Tools.get_binary_from_hex_string_byte_array(b);
                        m_n_flash_count = Tools.get_unsigned_int_from_8bytes_little_endian(b);
                        m_raw_flash_count = b;
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
                        m_raw_ksn = b;
                    }
                    else if(mode==Mode.mMPAN){//mandatory but none when card isn't credit card.
                        m_bin_masked_pan = Tools.get_binary_from_hex_string_byte_array(b);
                        m_raw_masked_pan = b;
                    }
                    else if(mode==Mode.mCHN){//option
                        m_bin_card_holder_name = Tools.get_binary_from_hex_string_byte_array(b);
                        m_raw_card_holder_name = b;
                    }
                    else if(mode==Mode.mCED){//option
                        m_bin_card_expiration_date = Tools.get_binary_from_hex_string_byte_array(b);
                        m_raw_card_expiration_date = b;
                    }
                    else if(mode==Mode.mMAC4){
                        if( b == null ){
                            b_result = false;
                            break;//exit while with error
                        }
                        m_bin_mac_4bytes = Tools.get_binary_from_hex_string_byte_array(b);
                        m_raw_mac_4bytes = b;
                    }
                    else if(mode==Mode.mISO1 || mode==Mode.mISO2 || mode==Mode.mISO3){
                        if( m_bins_en_iso == null ){
                            m_bins_en_iso = new byte[ParsingConst.CONST_THE_NUMBER_OF_TRACK][0];
                            m_raw_en_iso = new byte[ParsingConst.CONST_THE_NUMBER_OF_TRACK][0];
                        }
                        if(b == null ){
                            m_bins_en_iso[n_index] = new byte[0];//none track data
                            m_raw_en_iso[n_index] = new byte[0];//none track data
                        }
                        else {
                            byte[] cb = Tools.get_binary_from_hex_string_byte_array(b);
                            if(cb != null) {
                                m_bins_en_iso[n_index] = new byte[cb.length];
                                System.arraycopy(cb, 0, m_bins_en_iso[n_index], 0, cb.length);

                                m_raw_en_iso[n_index] = new byte[b.length];
                                System.arraycopy(b, 0, m_raw_en_iso[n_index], 0, b.length);
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
                m_raw_mac_4bytes = b;
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
     * get raw data except MAC 4bytes from response.
     * @param b_enable_CHN
     * @param b_enable_CED
     * @return binary data.
     */
    public byte[] get_raw_data_except_mac(boolean b_enable_CHN,boolean b_enable_CED){
        Queue<Byte> q = new LinkedList<>();
        //
        if( !m_b_parsable){
            return new byte[0];
        }
        //
        q.offer((byte)(0xff&ParsingTag.CONST_TAG_C));

        q.offer((byte)(0xff&ParsingTag.CONST_TAG_FCNT));
        Tools.push_back_bytes_to_queue(m_raw_flash_count,q);

        q.offer((byte)(0xff&ParsingTag.CONST_TAG_KSN));
        Tools.push_back_bytes_to_queue(m_raw_ksn,q);

        q.offer((byte)(0xff&ParsingTag.CONST_TAG_MPAN));
        Tools.push_back_bytes_to_queue(m_raw_masked_pan,q);

        if(b_enable_CHN){
            q.offer((byte)(0xff&ParsingTag.CONST_TAG_CHN));
        }
        if(m_bin_card_holder_name.length>0){
            Tools.push_back_bytes_to_queue(m_raw_card_holder_name,q);
        }

        if(b_enable_CED){
            q.offer((byte)(0xff&ParsingTag.CONST_TAG_CED));
        }
        if(m_bin_card_expiration_date.length>0){
            Tools.push_back_bytes_to_queue(m_raw_card_expiration_date,q);
        }

        for(int i=0; i<ParsingConst.CONST_THE_NUMBER_OF_TRACK; i++) {
            q.offer((byte) (0xff & ParsingTag.CONST_TAG_DISO));
            Tools.push_back_bytes_to_queue(m_raw_en_iso[i], q);
        }//end for

        q.offer((byte)(0xff&ParsingTag.CONST_TAG_MAC4));

        byte[] b = Tools.get_byte_array_from_queue(q);
        return b;
    }

    /**
     * get flash memory write count
     * @return int type write count.
     */
    public int get_flash_count_by_int(){
        return m_n_flash_count;
    }

    public byte[] get_flash_count(){
        return m_bin_flash_count;
    }
    public byte[] get_raw_flash_count(){
        return m_raw_flash_count;
    }

    /**
     * get Key serial number
     * @return binary type KSN.
     */
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

    public byte[] get_raw_ksn(){
        return m_raw_ksn;
    }
    /**
     * get Masked Primary Account Number.
     * @return binary type MPAN(Masked Primary Account Number)
     */
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
    public byte[] get_raw_mpan(){
        return m_raw_masked_pan;
    }

    /**
     * get Card Holder Name.
     * @return binary type CHN(Card Holder Name)
     */
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
    public byte[] get_raw_chn(){
        return m_raw_card_holder_name;
    }

    /**
     * get Card Expiration Date.
     * @return binary type CED(Card Expiration Date)
     */
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
    public byte[] get_raw_ced(){
        return m_raw_card_expiration_date;
    }

    /**
     * get 4 bytes Message Authentication Code.
     * @return binary type MAC4(Message Authentication Code)
     */
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
    public byte[] get_raw_mac_4bytes(){
        return m_raw_mac_4bytes;
    }

    /**
     * get plaintext length + encrypted track data.
     * @param n_track : 0~2 ([0,1,2] = [1,2,3] track)
     * @return the first byte : the size of the decrypted data.(127 ~ -128)
     * from second bytes : encrypted track data.
     */
    public byte[] get_encrypted_track_data(int n_track){
        byte[] bin = new byte[0];
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
            if(m_bins_en_iso[n_track].length <=0){
                continue;
            }

            bin = new byte[m_bins_en_iso[n_track].length];
            System.arraycopy(m_bins_en_iso[n_track],0,bin,0,bin.length);
        }while(false);
        return bin;
    }

    /**
     * get hex string the return of get_encrypted_track_data() method.
     * @param n_track : 0~2 ([0,1,2] = [1,2,3] track)
     * @return String type, hex string the return of get_encrypted_track_data() method.
     */
    public String get_encrypted_track_data_by_string(int n_track){
        byte[] bin = get_encrypted_track_data(n_track);
        if(bin != null){
            return Tools.get_hex_string_from_binary(bin);
        }
        else{
            return "";
        }
    }
    public byte[] get_raw_encrypted_track_data(int n_track){
        return m_raw_en_iso[n_track];
    }

}//the end of class
