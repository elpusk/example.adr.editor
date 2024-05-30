package kr.co.elpusk.example.keyinput;

import java.util.Queue;

public class Tools {
    /**
     * Queue<Byte>의 요소를 byte 배열로 변환하는 메서드
     *
     * @param queue Queue<Byte> 객체
     * @return byte 배열
     */
    static public byte[] get_byte_array_from_queue(Queue<Byte> queue) {
        if(queue == null){
            return null;
        }
        if(queue.isEmpty()){
            return null;
        }
        byte[] byteArray = new byte[queue.size()];
        int index = 0;
        for (Byte b : queue) {
            byteArray[index++] = b.byteValue();
        }
        return byteArray;
    }
    /**
     * compare x & y with byte type.
     * @param x converted to byte type in internal.
     * @param y converted to byte type in internal.
     * @return 0: (x==y)\
     * -1: if (x < y)
     * 1: if (x > y)
     */
    static public int compare_byte(int x, int y){
        int n_x = 0xFF&x;
        int n_y = 0xFF&y;
        return Integer.compare(n_x,n_y);
    }
    static public String add_e6_triple(String s_cipher){
        return "e6e6e6"+s_cipher;
    }

    /**
     * Hexadecimal 문자열을 받아 binary로 변환하여 byte 배열로 반환하는 메서드.
     *
     * @param s_hex 변환할 Hexadecimal 문자열
     * @return 변환된 byte 배열
     */
    static public byte[] get_binary_from_hex_string( String s_hex){
        int len = s_hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s_hex.charAt(i), 16) << 4)
                    + Character.digit(s_hex.charAt(i + 1), 16));
        }
        return data;
    }
    static public String get_hex_string_from_binary(byte[] bin) {
        StringBuilder hexString = null;
        do{
            if(bin == null){
                continue;
            }

            hexString = new StringBuilder(bin.length * 2);
            for (byte b : bin) {
                String hex = String.format("%02X", b);
                hexString.append(hex);
            }//end for
        }while(false);
        //
        if(hexString==null)
            return "";
        else
            return hexString.toString();
    }
    /**
     * Little-endian 방식의 byte[]을 int 값으로 변환하는 메서드.
     *
     * @param bin_8bytes Little-endian 방식, bin_8bytes 길이가 8인 byte array. bin_8bytes contains hex ascii code string
     * @return 변환된 int 값. negative is error.
     */
    static public int get_unsigned_int_from_8bytes_little_endian(byte[] bin_8bytes) {
        int n = -1;
        do{
            if(bin_8bytes==null){
                continue;
            }
            if(bin_8bytes.length != 8){
                continue;
            }

            StringBuilder hexString = new StringBuilder();
            for(int i=0; i<bin_8bytes.length; i +=2){
                hexString.insert(0,String.format("%c%c", (char)bin_8bytes[i],(char)bin_8bytes[i+1]));
            }

            // 헥스 문자열을 int로 변환
            n = Integer.parseUnsignedInt(hexString.toString(), 16);
        }while(false);
        return n;
    }

    /**
     * Little-endian 방식의 byte[]을 int 값으로 변환하는 메서드.
     *
     * @param bin_4bytes Little-endian 방식, bin_4bytes 길이가 4인 byte array. bin_4bytes contains hex ascii code string
     * @return 변환된 int 값. negative is error.
     */
    static public int get_unsigned_short_from_4bytes_little_endian(byte[] bin_4bytes) {
        int n = -1;
        do{
            if(bin_4bytes==null){
                continue;
            }
            if(bin_4bytes.length != 4){
                continue;
            }

            StringBuilder hexString = new StringBuilder();
            for(int i=0; i<bin_4bytes.length; i +=2){
                hexString.insert(0,String.format("%c%c", (char)bin_4bytes[i],(char)bin_4bytes[i+1]));
            }

            // 헥스 문자열을 int로 변환
            n = Integer.parseUnsignedInt(hexString.toString(), 16);
        }while(false);
        return n;
    }

    static public byte[] get_binary_from_hex_string_byte_array(byte[] bin_hex_string){
        byte[] bin = null;

        do{
            if(bin_hex_string ==null){
                continue;
            }
            if(bin_hex_string.length%2 != 0 ){
                continue;
            }
            bin = new byte[bin_hex_string.length/2];

            int n = 0;
            int j = 0;
            for(int i=0; i<bin_hex_string.length; i +=2){
                n = Integer.parseUnsignedInt(
                        String.format("%c%c", (char)bin_hex_string[i],(char)bin_hex_string[i+1]),
                        16
                );
                bin[j++] = (byte) ((byte) 0xff&n);
            }//end for

        }while(false);
        return bin;
    }

}//the end of class
