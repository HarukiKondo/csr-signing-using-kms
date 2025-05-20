// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * GenerateCDPSample - 証明書失効リスト配布ポイント（CDP）のサンプル生成クラス
 * 
 * このクラスは証明書失効リスト（CRL）分散ポイント拡張のASN.1構造を生成する
 * サンプルコードを提供します。これはX.509証明書に組み込むことができる
 * 拡張機能のデモンストレーションです。
 */
package com.amazonaws.kmscsr.examples;

import java.io.IOException;
import java.util.Base64;

import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

/**
 * 証明書失効リスト配布ポイント（CDP）のASN.1構造を生成するサンプルクラス
 */
public class GenerateCDPSample {

    /**
     * CRL配布ポイント拡張のASN.1エンコーディングを生成し、Base64形式で出力します
     * 
     * @param args コマンドライン引数（使用しません）
     * @throws IOException ASN.1エンコード処理中にエラーが発生した場合
     */
    public static void main(final String[] args) throws IOException {
        // CRL（証明書失効リスト）のURLを定義
        String crlUrl;
        crlUrl = "http://example.com/crl/0116z123-dv7a-59b1-x7be-1231v72571136.crl";
        
        // CRL配布ポイント（CDP）のASN.1構造を作成
        CRLDistPoint crlDistributionPoint = new CRLDistPoint(new DistributionPoint[] {
            new DistributionPoint(
                    // CRLのURLを含む配布ポイント名を設定
                    new DistributionPointName(new GeneralNames(new GeneralName(
                            // URL形式の識別子を使用
                            GeneralName.uniformResourceIdentifier,
                            crlUrl))),
                    null,  // 理由フィールドは未使用
                    null)  // CRL発行者フィールドは未使用
        });
        
        // ASN.1構造をエンコードしてBase64文字列として出力
        // この出力は証明書に埋め込むCRL拡張のフォーマットとして使用可能
        System.out.println(Base64.getEncoder().encodeToString(crlDistributionPoint.getEncoded()));
    }
}