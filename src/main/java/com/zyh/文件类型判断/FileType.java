package com.zyh.文件类型判断;

/**
 * @author yuanhao
 * @date 2018/6/16 16:29
 */
public enum FileType {

    /**
     * JPEG
     */
    JPEG("FFD8FF"),

    /**
     * PNG
     */
    PNG("89504E47"),

    /**
     * GIF
     */
    GIF("47494638"),

    /**
     * TIFF
     */
    TIFF("49492A00"),

    /**
     * Windows Bitmap
     */
    BMP("424D"),

    /**
     * CAD
     */
    DWG("41433130"),

    /**
     * Adobe Photoshop
     */
    PSD("38425053"),

    /**
     * XML
     */
    XML("3C3F786D6C"),

    /**
     * HTML
     */
    HTML("68746D6C3E"),

    /**
     * Adobe Acrobat
     */
    PDF("255044462D312E"),

    /**
     * ZIP Archive
     */
    ZIP("504B0304"),

    /**
     * RAR Archive
     */
    RAR("52617221"),

    /**
     * Wave
     */
    WAV("57415645"),

    /**
     * AVI
     */
    AVI("41564920");

    private String value = "";

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    FileType(String value) {

        this.value = value;
    }

}
