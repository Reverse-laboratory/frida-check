package com.example.anti_fr;

class CheckItem {
    String key;    // JSON 字段名
    String title;  // UI 标题
    String desc;   // 说明
    Boolean bad;   // true=风险 / false=安全 / null=未检测

    CheckItem(String key, String title, String desc) {
        this.key = key;
        this.title = title;
        this.desc = desc;
    }
}
