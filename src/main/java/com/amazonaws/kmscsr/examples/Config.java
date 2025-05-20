// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * Config - 設定ファイルを表すクラス
 * 
 * このクラスはJSON設定ファイル（cfg/kmscsr.json）から
 * 読み込まれる設定データを保持するためのPOJO（Plain Old Java Object）です。
 * Gsonを使用してJSONからJavaオブジェクトにマッピングされます。
 */
package com.amazonaws.kmscsr.examples;

import com.google.gson.annotations.SerializedName;

/**
 * JSONファイルから設定を読み込むためのクラス
 */
public class Config {

    /**
     * AWS KMSキー仕様（例："ECC_NIST_P256"）
     * JSONの "aws_key_spec" フィールドにマッピング
     */
    @SerializedName("aws_key_spec")
    private String awsKeySpec;

    /**
     * AWS KMSキーARN
     * JSONの "aws_key_arn" フィールドにマッピング
     * 形式: "arn:aws:kms:region:account-id:key/key-id"
     */
    @SerializedName("aws_key_arn")
    private String awsKeyArn;

    /**
     * 証明書のコモンネーム（CN）
     * JSONの "cert_common_name" フィールドにマッピング
     */
    @SerializedName("cert_common_name")
    private String certCommonName;

    /**
     * 証明書の国コード（C）
     * JSONの "cert_country_code" フィールドにマッピング
     */
    @SerializedName("cert_country_code")
    private String certCountryCode;

    /**
     * AWS KMSキー仕様を取得します
     * 
     * @return KMSキー仕様文字列（例："ECC_NIST_P256"）
     */
    public String getAwsKeySpec() {
        return awsKeySpec;
    }

    /**
     * AWS KMSキーARNを取得します
     * 
     * @return AWS KMSキーARN文字列
     */
    public String getAwsKeyArn() {
        return awsKeyArn;
    }

    /**
     * 証明書のコモンネーム（CN）を取得します
     * 
     * @return 証明書コモンネーム文字列
     */
    public String getCertCommonName() {
        return certCommonName;
    }

    /**
     * 証明書の国コード（C）を取得します
     * 
     * @return 証明書国コード文字列（例："JP"）
     */
    public String getCertCountryCode() {
        return certCountryCode;
    }
}