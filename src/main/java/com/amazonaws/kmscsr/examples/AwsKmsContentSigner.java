// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * AwsKmsContentSigner - AWS KMSを使用して署名を行うためのContentSigner実装
 * 
 * このクラスはBouncyCastleのContentSignerインターフェースを実装し、
 * AWS KMSサービスを使用して署名操作を行います。これにより秘密鍵が
 * AWS KMS内に保持されたままCSRに署名することができます。
 */
package com.amazonaws.kmscsr.examples;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.SignatureAlgorithmIdentifierFinder;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.SignRequest;

/**
 * BouncyCastleのContentSignerインターフェースを実装するクラス
 * AWS KMS サービスを使用して署名処理を行います
 */
public class AwsKmsContentSigner implements ContentSigner {

    // AWS KMS署名アルゴリズム名（例：ECDSA_SHA_256）
    private final String signingAlgorithm;
    // 署名対象データを収集するためのストリーム
    private final ByteArrayOutputStream outputStream;
    // AWS KMSサービスクライアント
    private final KmsClient awsKmsClient;
    // 署名に使用するAWS KMSキーのID
    private final String awsKmsKeyId;

    /**
     * コンストラクタ
     * 
     * @param inputSigningAlgorithm 署名アルゴリズム（例：ECDSA_SHA_256）
     * @param inputAwsKmsClient AWS KMSクライアントインスタンス
     * @param inputAwsKmsKeyId 署名に使用するKMSキーID
     */
    AwsKmsContentSigner(final String inputSigningAlgorithm, final KmsClient inputAwsKmsClient,
            final String inputAwsKmsKeyId) {
        awsKmsClient = inputAwsKmsClient;
        awsKmsKeyId = inputAwsKmsKeyId;
        signingAlgorithm = inputSigningAlgorithm;
        outputStream = new ByteArrayOutputStream();
    }

    /**
     * AWS KMS署名アルゴリズム名からBouncyCastle用のAlgorithmIdentifierを検索します
     * 
     * @param signingAlgorithm AWS KMS署名アルゴリズム名（例：ECDSA_SHA_256）
     * @return BouncyCastle用のAlgorithmIdentifierオブジェクト
     * 
     * @see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html">AWS KMS非対称キー仕様</a>
     */
    private static AlgorithmIdentifier findAlgorithmIdentifier(final String signingAlgorithm) {
        // BouncyCastleの署名アルゴリズム識別子ファインダーを作成
        final SignatureAlgorithmIdentifierFinder algorithmIdentifier = new DefaultSignatureAlgorithmIdentifierFinder();
        switch (signingAlgorithm) {
            // このプログラムはECDSA_SHA_256署名アルゴリズム用にテスト済みです。
            // 他のアルゴリズムを追加する場合はAWSドキュメントを参照：
            // https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html
            case "ECDSA_SHA_256":
                // AWS KMSのECDSA_SHA_256はBouncyCastleのSHA256WITHECDSAに対応
                return algorithmIdentifier.find("SHA256WITHECDSA");

            default:
                System.out.println("Signing Algorithm " + signingAlgorithm + " is not supported. Exiting ...");
                System.exit(-1);
                return null;
        }
    }

    /**
     * 署名で使用するアルゴリズム識別子を返します
     * ContentSignerインターフェースの実装
     * 
     * @return 署名アルゴリズムの識別子
     */
    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return findAlgorithmIdentifier(signingAlgorithm);
    }

    /**
     * 署名対象データを書き込むための出力ストリームを返します
     * ContentSignerインターフェースの実装
     * 
     * @return 署名対象データを収集する出力ストリーム
     */
    @Override
    public OutputStream getOutputStream() {
        return outputStream;
    }

    /**
     * 署名を実行し、署名バイトを返します
     * ContentSignerインターフェースの実装
     * この時点でAWS KMSへのAPI呼び出しが実行されます
     * 
     * @return AWS KMS署名操作の結果バイト配列
     */
    @Override
    public byte[] getSignature() {
        // 出力ストリームに収集されたデータをByteBufferにラップ
        final ByteBuffer message = ByteBuffer.wrap(outputStream.toByteArray());
        // AWS SDKのSdkBytes形式に変換
        final SdkBytes sdkBytes = SdkBytes.fromByteBuffer(message);

        // AWS KMS署名リクエストを構築
        final SignRequest signingRequest = SignRequest.builder().keyId(awsKmsKeyId).signingAlgorithm(signingAlgorithm)
                .message(sdkBytes).build();
        System.out.println("Signing request: " + signingRequest);

        // AWS KMSのSign() APIを呼び出して署名を実行
        // 秘密鍵はAWS KMS内に保持されたまま署名が実行される
        System.out.println("Calling Sign() API on AWS KMS ...");
        return awsKmsClient.sign(signingRequest).signature().asByteArray();
    }

}
