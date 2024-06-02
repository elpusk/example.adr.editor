package kr.co.elpusk.example.keyinput;

import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

interface DukptConst{
    int CONST_SIZE_KSN_BYTE = 10;
    int CONST_SIZE_IPEK_BYTE =16;
    int CONST_SIZE_SK_BYTE =16;
    int CONST_SIZE_MAC_RESPONSE_KEY_BYTE =16;
    int CONST_SIZE_DATA_ENCRYPT_KEY_BYTE = 16;

}
public class DukptTdes {
    private DukptTdes(){

    }

    boolean m_b_setup_ok = false;
    private byte[] m_bin_ksn = new byte[DukptConst.CONST_SIZE_KSN_BYTE];
    private byte[][] m_bin_ipek = new byte[2][DukptConst.CONST_SIZE_IPEK_BYTE];

    private byte[] m_bin_sk = new byte[DukptConst.CONST_SIZE_SK_BYTE];
    private byte[] m_bin_mac_rsp_key = new byte[DukptConst.CONST_SIZE_MAC_RESPONSE_KEY_BYTE];
    private byte[] m_bin_encrypt_key = new byte[DukptConst.CONST_SIZE_DATA_ENCRYPT_KEY_BYTE];
    boolean is_setup_ok(){
        return m_b_setup_ok;
    }

    public byte[] get_encrypt_key(){
        return m_bin_encrypt_key;
    }
    public DukptTdes(byte[] bin_ksn_10bytes,byte[][] bin_ipek_16bytes){
        m_b_setup_ok = false;

        do{
            if(bin_ksn_10bytes == null){
                continue;
            }
            if(bin_ksn_10bytes.length!=DukptConst.CONST_SIZE_KSN_BYTE){
                continue;
            }
            if(bin_ipek_16bytes == null){
                continue;
            }
            if(bin_ipek_16bytes.length != 2){
                continue;
            }
            if(bin_ipek_16bytes[0].length != DukptConst.CONST_SIZE_IPEK_BYTE){
                continue;
            }
            if(bin_ipek_16bytes[1].length != DukptConst.CONST_SIZE_IPEK_BYTE){
                continue;
            }

            System.arraycopy(bin_ksn_10bytes,0,m_bin_ksn,0,m_bin_ksn.length);
            for(int i=0; i<m_bin_ipek.length; i++){
                System.arraycopy(bin_ipek_16bytes[i],0,m_bin_ipek[i],0,m_bin_ipek[i].length);
            }//end for
            //
            if(!_generate_sk()){
                continue;
            }
            if(!_generate_mac_response_key()){
                continue;
            }
            if(!_generate_data_encryption_request_key()){
                continue;
            }
            //
            m_b_setup_ok = true;
        }while(false);
    }

    public byte[] generate_mac_4bytes(byte[] bin_data){
        byte[] mac8 = new byte[8];
        byte[] mac4 = new byte[4];
        if(!DukptTdes.dukptGenerateMac(mac8,m_bin_mac_rsp_key,bin_data) ){
            mac4 = new byte[0];
        }
        else{
            System.arraycopy(mac8, 0, mac4, 0, mac4.length);
        }

        return mac4;
    }

    private boolean _generate_sk(){

        boolean b_result = true;

        try {
            byte[] enCnt = {
                    (byte) (m_bin_ksn[7] & 0x1f),
                    m_bin_ksn[8],
                    m_bin_ksn[9]
            };

            byte[] ipek = new byte[m_bin_ipek[0].length];
            for (int i = 0; i < m_bin_ipek[0].length; i++) {
                ipek[i] = (byte) ((byte) m_bin_ipek[0][i] ^ (byte) m_bin_ipek[1][i]);
            }

            byte[] ksnBase = Arrays.copyOf(m_bin_ksn, 10);
            ksnBase[7] &= (byte) 0xe0;
            ksnBase[8] = 0;
            ksnBase[9] = 0;

            byte[] ksnIn = new byte[10];
            byte[] keyIn = Arrays.copyOf(ipek, 16);
            byte[] keyOut = new byte[16];
            byte cMask = 0x10;

            for (int i = 0; i < 5; i++) {
                if ((enCnt[0] & cMask) != 0) {
                    System.arraycopy(ksnBase, 0, ksnIn, 0, 10);
                    ksnIn[7] |= cMask;

                    DukptTdes._dukptBlackbox(keyOut, keyIn, ksnIn);
                    System.arraycopy(keyOut, 0, keyIn, 0, 16);
                    System.arraycopy(ksnIn, 0, ksnBase, 0, 10);
                }
                cMask = Tools.byte_op_right_shift(cMask,1);//cMask >>= 1;
            }

            cMask = (byte) 0x80;
            for (int i = 0; i < 8; i++) {
                if ((enCnt[1] & cMask) != 0) {
                    System.arraycopy(ksnBase, 0, ksnIn, 0, 10);
                    ksnIn[8] |= cMask;

                    DukptTdes._dukptBlackbox(keyOut, keyIn, ksnIn);
                    System.arraycopy(keyOut, 0, keyIn, 0, 16);
                    System.arraycopy(ksnIn, 0, ksnBase, 0, 10);
                }
                cMask = Tools.byte_op_right_shift(cMask,1);//cMask >>= 1;
            }

            cMask = (byte) 0x80;
            for (int i = 0; i < 8; i++) {
                if ((enCnt[2] & cMask) != 0) {
                    System.arraycopy(ksnBase, 0, ksnIn, 0, 10);
                    ksnIn[9] |= cMask;

                    DukptTdes._dukptBlackbox(keyOut, keyIn, ksnIn);
                    System.arraycopy(keyOut, 0, keyIn, 0, 16);
                    System.arraycopy(ksnIn, 0, ksnBase, 0, 10);
                }
                cMask = Tools.byte_op_right_shift(cMask,1);//cMask >>= 1;
            }

            System.arraycopy(keyOut, 0, m_bin_sk, 0, 16);
        }
        catch (Exception e){
            e.printStackTrace();    //예외정보 출력
            b_result = false;
        }
        return true;
    }

    private boolean _generate_mac_response_key(){
        boolean b_result =true;

        byte[] macResponseKeyP = {
                0x00, 0x00, 0x00, 0x00, (byte) 0xff, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, (byte) 0xff, 0x00, 0x00, 0x00
        };

        for (int i = 0; i < 16; i++) {
            m_bin_mac_rsp_key[i] = (byte) (m_bin_sk[i] ^ macResponseKeyP[i]);
        }
        return b_result;
    }
    private boolean _generate_data_encryption_request_key(){
        boolean b_result =true;

        try{
            byte[] dataEncryptionKeyP = {
                    0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0xff, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0xff, 0x00, 0x00
            };

            byte[] dataEncryptionKeyVar = new byte[16];
            for (int i = 0; i < 16; i++) {
                dataEncryptionKeyVar[i] = (byte) (m_bin_sk[i] ^ dataEncryptionKeyP[i]);
            }

            m_bin_encrypt_key = DukptTdes.des3EncryptECB(dataEncryptionKeyVar, dataEncryptionKeyVar);
            /*
            byte[] leftKey = Arrays.copyOfRange(dataEncryptionKeyVar, 0, 8);
            byte[] rightKey = Arrays.copyOfRange(dataEncryptionKeyVar, 8, 16);

            // DES3 encryption
            byte[] encryptedLeft = DukptTdes.des3EncryptECB(leftKey, dataEncryptionKeyVar);
            byte[] encryptedRight = DukptTdes.des3EncryptECB(rightKey, dataEncryptionKeyVar);

            System.arraycopy(encryptedLeft, 0, m_bin_encrypt_key, 0, 8);
            System.arraycopy(encryptedRight, 0, m_bin_encrypt_key, 8, 8);
            */
        }
        catch (Exception e){
            b_result = false;
        }
        return b_result;
    }

    private static void _dukptBlackbox(byte[] newSessionKey, byte[] curSessionKey, byte[] ksn) throws Exception {
        byte[] ksnPrime = new byte[10];
        byte[] ksnPrimeMask = {0, 0, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xe0, 0, 0};

        // generate ksn prime
        for (int i = 0; i < 10; i++) {
            ksnPrime[i] = (byte) (ksn[i] & ksnPrimeMask[i]);
        }

        // generate key modification
        byte[] ksnMod = new byte[8];
        for (int i = 0; i < 8; i++) {
            ksnMod[i] = ksnPrime[i + 2];
        }

        byte[] ksnCountMask = {0, 0, 0, 0, 0, 0, 0, 0x1F, (byte) 0xFF, (byte) 0xFF}; // 21 bits mask

        byte[] ksnCount = new byte[8];
        for (int i = 0; i < 8; i++) {
            ksnCount[i] = (byte) (ksn[i + 2] & ksnCountMask[i + 2]);
        }

        for (int i = 0; i < 8; i++) {
            ksnMod[i] |= ksnCount[i];
        }

        // generates session key LSB 8bytes (right of session key)
        byte[] leftKey = Arrays.copyOfRange(curSessionKey, 0, 8);
        byte[] rightKey = Arrays.copyOfRange(curSessionKey, 8, 16);

        byte[] msg = new byte[8];
        for (int i = 0; i < 8; i++) {
            msg[i] = (byte) (rightKey[i] ^ ksnMod[i]);
        }

        byte[] out = DukptTdes.desEncryptECB(leftKey, msg);

        byte[] skLsb8 = new byte[8]; // CR2
        for (int i = 0; i < 8; i++) {
            skLsb8[i] = (byte) (out[i] ^ rightKey[i]);
        }

        // generates session key MSB 8bytes (left of session key)
        byte[] skMod = new byte[16];
        byte[] skP = {
                (byte) 0xc0, (byte) 0xc0, (byte) 0xc0, (byte) 0xc0, 0, 0, 0, 0,
                (byte) 0xc0, (byte) 0xc0, (byte) 0xc0, (byte) 0xc0, 0, 0, 0, 0
        };
        for (int i = 0; i < 16; i++) {
            skMod[i] = (byte) (curSessionKey[i] ^ skP[i]);
        }

        leftKey = Arrays.copyOfRange(skMod, 0, 8);
        rightKey = Arrays.copyOfRange(skMod, 8, 16);

        for (int i = 0; i < 8; i++) {
            msg[i] = (byte) (rightKey[i] ^ ksnMod[i]);
        }

        out = DukptTdes.desEncryptECB(leftKey, msg);

        byte[] skMsb8 = new byte[8]; // CR1
        for (int i = 0; i < 8; i++) {
            skMsb8[i] = (byte) (out[i] ^ rightKey[i]);
        }

        // generates new session key
        System.arraycopy(skMsb8, 0, newSessionKey, 0, 8);
        System.arraycopy(skLsb8, 0, newSessionKey, 8, 8);
    }

    static public byte[] desEncryptECB(byte[] key, byte[] data) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }
    static public byte[] des3EncryptECB(byte[] key, byte[] data) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "DESede");
        Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }
    static public boolean dukptGenerateMac(byte[] mac8, byte[] macEncryptionKey, byte[] message){
        boolean b_result =true;

        try {
            byte[] macKey = Arrays.copyOf(macEncryptionKey, 16);
            byte[] data = new byte[8];
            byte[] dataIn = new byte[8];
            int nLoop = message.length / 8;

            Arrays.fill(dataIn, (byte) 0);

            Cipher desCipher = Cipher.getInstance("DES/ECB/NoPadding");

            for (int i = 0; i < nLoop; i++) {
                System.arraycopy(message, i * 8, data, 0, 8);

                for (int j = 0; j < 8; j++) {
                    dataIn[j] ^= data[j];
                }

                SecretKeySpec macKeySpec = new SecretKeySpec(Arrays.copyOfRange(macKey, 0, 8), "DES");
                desCipher.init(Cipher.ENCRYPT_MODE, macKeySpec);
                dataIn = desCipher.doFinal(dataIn);
            }

            if (message.length % 8 != 0) {
                Arrays.fill(data, (byte) 0);
                System.arraycopy(message, nLoop * 8, data, 0, message.length % 8);

                for (int j = 0; j < 8; j++) {
                    dataIn[j] ^= data[j];
                }

                SecretKeySpec macKeySpec = new SecretKeySpec(Arrays.copyOfRange(macKey, 0, 8), "DES");
                desCipher.init(Cipher.ENCRYPT_MODE, macKeySpec);
                dataIn = desCipher.doFinal(dataIn);
            }

            SecretKeySpec macKeySpecPart2 = new SecretKeySpec(Arrays.copyOfRange(macKey, 8, 16), "DES");
            desCipher.init(Cipher.DECRYPT_MODE, macKeySpecPart2);
            dataIn = desCipher.doFinal(dataIn);

            SecretKeySpec macKeySpec = new SecretKeySpec(Arrays.copyOfRange(macKey, 0, 8), "DES");
            desCipher.init(Cipher.ENCRYPT_MODE, macKeySpec);
            dataIn = desCipher.doFinal(dataIn);

            System.arraycopy(dataIn, 0, mac8, 0, 8);
        }
        catch (Exception e){
            e.printStackTrace();
            b_result = false;
        }
        return b_result;
    }

    static public byte[] decrypt3DESCBC(byte[] key, byte[] iv, byte[] encryptedData){
        byte[] out = new byte[0];
        if (key.length != 16 && key.length != 24) {
            return out;
        }

        try {
            // Prepare the 24-byte key for 3DES
            byte[] desKey = new byte[24];
            System.arraycopy(key, 0, desKey, 0, 16);
            if (key.length == 16) {
                System.arraycopy(key, 0, desKey, 16, 8);
            } else {
                System.arraycopy(key, 16, desKey, 16, 8);
            }

            // Initialize the cipher
            SecretKeySpec keySpec = new SecretKeySpec(desKey, "DESede");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

            // Decrypt the data
            out = cipher.doFinal(encryptedData);
        }
        catch (Exception e){
            e.printStackTrace();
            out = new byte[0];
        }

        return out;
    }
}
