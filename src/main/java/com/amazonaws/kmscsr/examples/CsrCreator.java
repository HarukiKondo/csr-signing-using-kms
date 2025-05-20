// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * CsrCreator - メインクラス
 * 
 * このクラスは AWS KMS を使用した証明書署名要求 (CSR) の作成を担当します。
 * 主な機能:
 * - 設定ファイルの読み込み
 * - AWS KMS との通信
 * - 公開鍵の取得
 * - CSR の作成と署名
 * - 署名された CSR の PEM 形式への変換
 */
package com.amazonaws.kmscsr.examples;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.MiscPEMGenerator;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.endpoints.internal.Arn;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * CSR作成のメインクラス
 * このクラスはCSRの作成と署名のプロセスを統括します
 */
public class CsrCreator {

    // AWS KMSクライアント
    private KmsClient awsKmsClient;
    // KMSキーID（ARNから抽出される）
    private String keyId;
    // KMSから取得した公開鍵のバイト配列
    private byte[] publicKeyBytes;
    // KMSキーのリージョン
    private String kmsRegion;
    // Java Cryptography Extension（JCE）で使用する署名アルゴリズム名
    private String jceSigningAlgorithm;
    // 証明書のコモンネーム（Common Name）
    private String certCommonName;
    // 証明書の国コード（Country Code）
    private String certCountryCode;
    // AWS KMSで使用する署名アルゴリズム名
    private String signingAlgorithm;
    // AWS KMSキー仕様（例：ECC_NIST_P256）
    private String awsKeySpec;

    /**
     * コンストラクタ
     * BouncyCastleセキュリティプロバイダーの初期化とログレベルの設定を行います
     */
    public CsrCreator() {
        // Log4jの基本設定を初期化
        BasicConfigurator.configure();
        // ログレベルをエラーのみに設定
        Logger.getRootLogger().setLevel(Level.ERROR);
        // BouncyCastleプロバイダーをJavaセキュリティに追加
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * メインメソッド - アプリケーションのエントリーポイント
     * CSR作成の全体的なプロセスをステップバイステップで実行します
     * 
     * @param args コマンドライン引数（使用しません）
     */
    public static void main(final String[] args) {
        System.out.println("Running CSR creation and signing using AWS KMS util ... ");

        // CsrCreatorインスタンスを生成
        final CsrCreator csrCreator = new CsrCreator();
        // 設定ファイルを読み込み
        csrCreator.readConfig();
        // AWS KMSから公開鍵を取得
        csrCreator.fetchAwsKmsPublicKey();
        // CSRを作成して署名
        final String pemFormattedCsr = csrCreator.createAndSignCsr();
        // 生成されたPEM形式のCSRを出力
        System.out.println("PEM formatted CSR:\n" + pemFormattedCsr);

        // AWS KMSクライアントを閉じる
        csrCreator.awsKmsClient.close();
        System.exit(0);
    }

    /**
     * AWS KMS署名アルゴリズム名からJCE準拠の署名アルゴリズム名を取得します
     * 
     * @param signingAlgorithm AWS KMSの署名アルゴリズム（例：ECDSA_SHA_256）
     * @return JCE準拠の署名アルゴリズム名（例：EC）
     * @throws IllegalArgumentException サポートされていない署名アルゴリズムが指定された場合
     * 
     * @see <a href="https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#keyfactory-algorithms">JCEアルゴリズム名一覧</a>
     */
    private static String getJceKeyFactoryAlgorithmName(final String signingAlgorithm) {
        // このコードは楕円曲線（Elliptic Curve）アルゴリズム用にテスト済み
        // 他のアルゴリズムをサポートする場合はここを拡張できます
        if (signingAlgorithm.startsWith("EC")) {
            return "EC";
        }

        // サポートされていないアルゴリズムの場合はエラーメッセージをスロー
        String errMsg = "Signing Algorithm " + signingAlgorithm + " is not supported. " +
                "Pls. see README for supported signing algorithms";
        throw new IllegalArgumentException(errMsg);
    }

    /**
     * 設定ファイル <project-root>/cfg/kmscsr.json を読み込み、内容を解析します
     * 設定項目：
     * - AWS KMS キーARN
     * - AWS キー仕様
     * - 証明書コモンネーム
     * - 証明書国コード
     */
    private void readConfig() {
        final String userDir = System.getProperty("user.dir");
        System.out.println("Project Directory: " + userDir);
        final String cfgFilePathName = userDir + "/cfg/kmscsr.json";

        System.out.println("Reading config file: " + cfgFilePathName);
        String cfgJsonString = null;

        try {
            cfgJsonString = new String(Files.readAllBytes(Paths.get(cfgFilePathName)), StandardCharsets.UTF_8);
        }
        catch (IOException e) {
            System.out.println("ERROR: Error reading config file kmscsr.json.\n" +
                    "Please ensure that the file is present under <project-root>/cfg/kmscsr.json. Exiting ...");
            e.printStackTrace();
            System.exit(-1);
        }

        System.out.println("Found config file " + cfgFilePathName);
        System.out.println("Read config contents " + cfgJsonString);

        final Gson gson = new Gson();
        Config cfgJsonObj = null;
        try {
            cfgJsonObj = gson.fromJson(cfgJsonString, Config.class);
        }
        catch (JsonSyntaxException e) {
            System.out.println("ERROR: Invalid JSON syntax in <project-root>/cfg/kmscsr.json. Exiting ...\n");
            System.exit(-1);
        }

        // Extract signing algorithm from config
        System.out.println("Extracting parameters from config file ...");

        awsKeySpec = cfgJsonObj.getAwsKeySpec();
        System.out.println("AWS Key Spec: " + awsKeySpec);

        signingAlgorithm = getSigningAlgorithmFromAwsKeySpec(awsKeySpec);
        System.out.println("Signing algorithm: " + signingAlgorithm);

        jceSigningAlgorithm = getJceKeyFactoryAlgorithmName(signingAlgorithm);
        System.out.println("JCE compliant signing algorithm: " + jceSigningAlgorithm);

        // Extract Key Id and region from Key ARN read from config
        // Key ARN format: "arn:aws:kms:us-east-1:012345678901:key/some-key-id"
        final Optional<Arn> awsKmsKeyArn = Arn.parse(cfgJsonObj.getAwsKeyArn());
        if (!awsKmsKeyArn.isPresent()) {
            System.out.println("ERROR: Key ARN provided in config could not be parsed: " + cfgJsonObj.getAwsKeyArn());
            System.out.println("Fix configuration. Exiting ...");
            System.exit(-1);
        }

        kmsRegion = awsKmsKeyArn.get().region();
        System.out.println("AWS KMS Region: " + kmsRegion);

        // For key ARN example:
        // "arn:aws:kms:your-aws-region:012345678901:key/123456-1234-1234-1234-1234567890",
        // The Arn object resource() list is returned as: [key, 123456-1234-1234-1234-1234567890]
        final List<String> resourceList = awsKmsKeyArn.get().resource();
        keyId = resourceList.get(1); // Second item in list contains keyId
        System.out.println("AWS KMS Key Id: " + keyId);

        // Extract CSR input fields from config
        certCommonName = cfgJsonObj.getCertCommonName();
        System.out.println("Cert Common Name: " + certCommonName);

        certCountryCode = cfgJsonObj.getCertCountryCode();
        System.out.println("Cert Country Code: " + certCountryCode);

        // Basic syntax checking of CN, C names for brevity: Value should not contain separators and equal(=) sign
        // Formal Name syntax is defined in: https://www.rfc-editor.org/rfc/rfc1779.html#section-2.3
        Pattern nameRegexValidationPattern = Pattern.compile("[,;=]");

        Matcher commonNameRegexMatcher = nameRegexValidationPattern.matcher(certCommonName);
        if (commonNameRegexMatcher.find()) {
            System.out.println("ERROR: cert_common_name in kmscsr.json contains illegal characters " + certCommonName);
            System.out.println("Fix configuration. Exiting ...");
            System.exit(-1);
        }

        Matcher countryCodeRegexMatcher = nameRegexValidationPattern.matcher(certCountryCode);
        if (countryCodeRegexMatcher.find()) {
            System.out.println(
                    "ERROR: cert_country_code in kmscsr.json contains illegal characters " + certCountryCode);
            System.out.println("Fix configuration. Exiting ...");
            System.exit(-1);
        }
    }

    /**
     * 設定ファイルで指定されたキーARNに関連する公開鍵をAWS KMSから取得します
     * この公開鍵は後でCSRの作成に使用されます
     */
    private void fetchAwsKmsPublicKey() {
        System.out.println("Fetching public key from AWS KMS ...");
        // 指定されたリージョンのAWS KMSクライアントを作成
        awsKmsClient = KmsClient.builder().region(Region.of(kmsRegion)).build();
        // 公開鍵取得のためのリクエストを構築
        final GetPublicKeyRequest getPublicKeyRequest = GetPublicKeyRequest.builder().keyId(keyId).build();
        // AWS KMSに公開鍵を要求
        final SdkBytes publicKeySdkBytes = awsKmsClient.getPublicKey(getPublicKeyRequest).publicKey();
        // バイト配列として公開鍵を保存
        publicKeyBytes = publicKeySdkBytes.asByteArray();
    }

    /**
     * AWS KMSキー仕様から対応する署名アルゴリズムを返します
     * 
     * @param awsKeySpec AWS KMSキー仕様（例：ECC_NIST_P256）
     * @return 対応する署名アルゴリズム（例：ECDSA_SHA_256）
     * @throws IllegalArgumentException サポートされていないキー仕様が指定された場合
     */
    private String getSigningAlgorithmFromAwsKeySpec(final String awsKeySpec) {
        // AWS KMSキー仕様文字列はAWSドキュメントから派生しています：
        // https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html
        if (awsKeySpec.equals("ECC_NIST_P256")) {
            return "ECDSA_SHA_256";
        }
        // サポートされていないキー仕様の場合はエラー
        throw new IllegalArgumentException("AWS Key Spec " + awsKeySpec + " is not supported");
    }

    /**
     * CSRオブジェクトを作成し、AWS KMS非対称キーで署名します
     * 
     * @return PEM形式の署名済みCSR文字列
     */
    private String createAndSignCsr() {
        // 公開鍵バイトをASN.1形式にエンコードし、JCE準拠のPublicKeyオブジェクトを生成
        System.out.println("Encoding public key in ASN.1 format ...");
        // X.509エンコーディング形式で公開鍵を準備
        final X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey;
        try {
            // 指定された署名アルゴリズムとBouncyCastleプロバイダーを使用して公開鍵オブジェクトを生成
            publicKey = KeyFactory.getInstance(jceSigningAlgorithm, BouncyCastleProvider.PROVIDER_NAME)
                    .generatePublic(publicKeySpec);
        }
        catch (InvalidKeySpecException e) {
            // 設定で提供されたキー仕様が無効な場合
            throw new IllegalArgumentException("Key spec provided in config is invalid", e);
        }
        catch (NoSuchAlgorithmException e) {
            // 設定で提供された署名アルゴリズムが無効な場合
            throw new IllegalArgumentException("Signing algorithm (part of key spec) provided in config is invalid", e);
        }
        catch (NoSuchProviderException e) {
            // BouncyCastleプロバイダが見つからない場合（内部エラー）
            throw new IllegalStateException("Internal program error. Try rebuilding program", e);
        }

        System.out.println("Creating CSR ...");
        // X.500識別名（Distinguished Name）を構築
        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        // コモンネーム（CN）を追加
        nameBuilder.addRDN(BCStyle.CN, certCommonName);
        // 国コード（C）を追加
        nameBuilder.addRDN(BCStyle.C, certCountryCode);
        // PKCS#10証明書署名要求（CSR）ビルダーを作成
        JcaPKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(nameBuilder.build(),
                publicKey);

        // 拡張機能ジェネレータを作成
        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        try {
            // BasicConstraints拡張を追加（CA=false：この証明書はCA証明書ではない）
            extensionsGenerator.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
        }
        catch (IOException e) {
            System.out.println("ERROR: Potential error in certificate parameters in config. Exiting ...");
            e.printStackTrace();
            System.exit(-1);
        }
        // CSRに拡張機能を属性として追加
        csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());

        System.out.println("Signing CSR using AWS KMS ...");
        // AWS KMS ContentSignerを使用してCSRを構築し署名
        // 秘密鍵はAWS KMS内に保持されたまま署名が行われる
        PKCS10CertificationRequest csr = csrBuilder
                .build(new AwsKmsContentSigner(signingAlgorithm, awsKmsClient, keyId));

        System.out.println("Converting CSR to PEM format ...");
        // CSRをPEM形式のオブジェクトに変換するためのジェネレータを作成
        PemObjectGenerator miscPEMGenerator = new MiscPEMGenerator(csr);
        // 文字列出力用のWriterを作成
        StringWriter csrStringWriter = new StringWriter();

        // PEMWriterを使用してCSRをPEM形式で書き込み
        try (PemWriter csrPemWriter = new PemWriter(csrStringWriter)) {
            csrPemWriter.writeObject(miscPEMGenerator);
        }
        catch (IOException e) {
            System.out.println("ERROR: Internal program error in PEM formatting. Exiting ...");
            e.printStackTrace();
            System.exit(-1);
        }

        // PEM形式の文字列を返す
        return csrStringWriter.toString();
    }
}