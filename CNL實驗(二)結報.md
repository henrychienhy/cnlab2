# CNL實驗(二)結報

## 組員
* B06703084 邢皓霆
* B07508005 鄭仲語
* B07902023 簡宏曄
* B08902057 陳奕瑄
* B08902071 塗季芸
* B08902029 陳咏誼

## WLAN Authentication Mechanism
以下分別對於 WEP、EAP、WPA 做介紹。

### 認證機制的運作原理
#### WEP（Wired Equivalent Protocol, 有線等效協定）
&#160; &#160; &#160; &#160;WEP 是由 IEEE 為 802.11 設計的一套對等式線性加解密的機制。標準的 64 bits WEP 的加密方法是使用由虛擬亂數產生器所產生的 24 bits IV（Initial Vector, 初始向量值） 以及 40 bits 的共享密鑰（Shared Secret Key）作為鑰匙，經過 RC4 ( Rivest Cipher 4 ) 串流加密法生成 stream key，再用 stream key 加密明文，並把 IV 隨著密文一起送出。驗證傳輸訊息完整與否則是使用線性的雜湊演算法，CRC-32 演算法。

#### EAP（Extensible Authentication Protocol, 擴展認證協議）
&#160; &#160; &#160; &#160;EAP 是一個身分認證的框架，為一系列驗證方法 ( EAP methods ) 的集合，設計理念是滿足任何 link layer 的身份驗證需求，支持多種 link layer 認證方式。
EAP 可分為四層：
- EAP 底層：負責轉發和接收被認證端（peer）和認證端之間的EAP frames
- EAP 層：接收和轉發通過底層的 EAP 包
- EAP 對等認證層：在 EAP 對等層和 EAP 認證層之間對到來的 EAP 包進行多路分離
- EAP 方法層：實現認證算法接收和轉發 EAP 信息

&#160; &#160; &#160; &#160;許多認證協定，如 EAP-TLS ( EAP Transport Layer Security ) 和 EAP-PWD ( EAP Password ) 等都是基於 EAP 所衍生。其中 EAP-SIM ( EAP Subscriber Identity Module ) 和 LEAP ( Lightweight Extensible Authentication Protocol ) 十分適用於資源受限的設備。

#### WPA（Wi-Fi Protected Access, Wi-Fi存取保護）
&#160; &#160; &#160; &#160;WPA 是由 Wi-Fi Alliance 所開發的一個過渡標準，目的是為了解決在 WEP 中發現的一些嚴重瑕疵，如加密的問題。WPA 可以符合 IEEE  802.11 無線安全性通訊協定，根據金鑰使用的不同可分成兩種版本，分別是 WPA-Personal 及 WPA-Enterprise。WPA-Personal 或稱 WPA2-Personal，是為家庭和小型辦公網路而設計的，其使用較不安全的預共享金鑰模式 （pre-shared key, PSK），讓同一無線路由器底下的每個使用者都使用同一把金鑰。WPA-Enterprise，或稱 WPA2-Enterprise 版本，則是為企業網路所設計的，其使用一個 802.1X 認證伺服器來分發不同的金鑰給各個終端使用者。

### 目前市面上對於無線區域網路所提出之認證機制其優缺點
#### WEP（Wired Equivalent Protocol, 有線等效協定）
**優點：**
- 機密性：採用 RC4 加密演算法，此加密機制可以用來保護所有的協定標頭（header）資訊。
- 安全性：協定規格會針對每一個傳送的封包完整性做 32 位元的 CRC 檢查。
- 非強制性：使用者可依其需要來選用與否，並在開放系統或認證下均可選用。

**缺點：**
- 身份認證：WEP 僅提供 AP 單向認證 ( One-way authentication ) 機制，連線者無法證明 AP 的真實身份，因此在 WEP 身份認證的過程中，可能會遭到中間人（man-in-the-middle）攻擊。
- IV 的限制：WEP 將 IV 定義為 24 位值，以純文字形式隨 WEP 密鑰一起傳輸的 40 位 WEP 種子值生成的，但 WEP 沒有指出由誰來建立該值，如此便可以由值為零的 IV 開始並以易於猜測密鑰的方式生成更多的 IV。
- 靜態 WEP 密鑰：當在多個資料上同時使用帶有相同 WEP 密鑰的相同 IV 時，IV 衝突就產生所謂的弱 WEP 密鑰。分析眾多此類弱密鑰，可以反推出使用者所指定的密鑰，並進行攻擊 WEP。至今已有許多破解 WEP 的工具，如 WEPCrack、AirSnort 等。
- 此外，基台回應給使用者的 challenge 訊息未加密，因此監聽無線網路的攻擊者就可以同時獲得未加密的原文與加密後的密文，這些資料可以幫助攻擊者找出可能的密鑰或是解開其他加密過的封包。由於 WEP 已有許多證據證明提及的漏洞，會建議不要使用 WEP 以免遭到攻擊。
- 針對封包完整性，WEP 使用 CRC 檢查完整性。然而 CRC 並不安全，在不知道 WEP 金鑰的情況下，要篡改所載資料和對應的CRC 是可能的。想要獲得更安全的 WEP 版本，有賴於更好的亂數生成技術。

#### EAP（Extensible Authentication Protocol, 擴展認證協議）
**優點：**
- 架構靈活：在認證方和被認證方交互足夠多的信息之後，才會決定出一種具體的認證方法。認證方不用支持所有的認證方法，因為 EAP 架構允許使用一個後端的認證伺服器，此時認證方將在客戶端和認證伺服器之間透傳消息。
- 雙向認證 ( Two-way authentication )：不僅認證服務器需要對請求方的身份進行認證，請求方也必須對認證服務器的身份進行認證，以防止自己提供的用戶名和密碼被非法或假冒的認證服務器竊取。這種相互認證可避免中間人攻擊。
- 傳輸層安全性（EAP-TLS）：提供用戶端與網路之間根據憑證的共同驗證。它根據用戶端及伺服器端的憑證來執行驗證，而且可以用來動態地產生根據使用者及根據連接作業的 WEP 金鑰，進而保護無線區域網路用戶端與存取點之間後續通訊的安全。

**缺點：**
- 管理困難（EAP-TLS）：用戶端與伺服器端都必須管理相關的憑證，因此大型的無線區域網路系統可能會面臨管理上的困難。

#### WPA（Wi-Fi Protected Access, Wi-Fi存取保護）
- WPA 超越 WEP 的主要改進就是在使用中可以動態改變金鑰的「臨時金鑰完整性協定」（Temporal Key Integrity Protocol，TKIP），加上更長的 initial vector，這可以防禦針對 WEP 的金鑰擷取攻擊。
- 除了認證跟加密外，WPA 對於資料的完整性也提供了巨大的改進。WPA 使用了 Michael 演算法 ( Sequence Counter ) 來驗證完整性，若是封包的順序不符合規定時，就會被自動拒收，可以避免重放攻擊（Replay attack）。
- WPA 的密碼長度介在 8 到 63 個字元之間，還是有可能透過以下幾種方式破解：
	1. 蠻力搜尋 ( Brute-force ) 或字典式攻擊 ( dictionary attack )
	2. Exploit the vulnerability in WPS （Wi-Fi Protected Setup）
- 2018 年由提出的 WPA3 進一步改善 WiFi 連線的安全性，除增加密碼長度上限以增加密碼強度外，更用對等實體同步驗證（ Simultaneous Authentication of Equals, SAE ) 以取代 WPA2 舊有會遭受 KRACK 攻擊的加密方式。

### 說明對於所提出之認證機制其漏洞預防措施為何
#### WEP（Wired Equivalent Protocol, 有線等效協定）
**漏洞：**
因為同一個鑰匙不能在 RC4 重複使用，所以使用 IV 的目的就是要避免鑰匙重複，然而標準的 24 位元的 IV 並沒有長到足以保證在忙碌的網路上不會重複，且 IV 的使用方式也使其可能遭受到關連式鑰匙攻擊 ( Related-key attack )。

透過 IV 和 RC4，可以推算出部分的 Key Stream 進而推算出部分的 Shared Key。只要蒐集大量包含 IV 的 Frame，便可以把 Shared Key 推算出來。 

**預防措施：**
* 使用加密的隧道協議 ( tunneling protocols )，如 IPSec、Secure Shell，可在不安全的網路上提供安全的數據傳輸。
* 改使用更加安全的 WPA 或 WPA2 協議
* 對於可用於一些不能處理 WPA 或 WPA2 的硬體設備，可使用 WEP2 來將 IV 和密鑰值都擴增到 128 位 (不過此修正仍保留原本 WEP 的缺點)
* 使用 WEPplus ( 也被稱為 WEP+ ) 來提升安全性，但只有在設備兩端都可使用 WEPplus 下才能執行，且其仍然無法抵擋重放攻擊或 IV 的統計攻擊
* 使用動態 WEP ( dynamic WEP )，其動態改變 WEP 的密鑰，可避免原本 WEP 的靜態密鑰而可能導致的攻擊。

#### EAP（Extensible Authentication Protocol, 擴展認證協議）
**漏洞：**
* 部分 EAP 的方法容易受到字典攻擊 ( directory attack )，是因為有這些 EAP 的實作方式使用共享密鑰作爲驗證的方式，如 LEAP ( Lightweight Extensible Authentication Protocol )，LEAP 使用未加密的 MS-CHAPv1，使用 MS-CHAPv1 容易受到離線的字典攻擊。若是選擇的共享密鑰強度不夠高，便很容易用字典攻擊來破解。
* EAP 的實作仰賴 RADIUS 的明文認證 (  clear-text authentication )，因此容易暴露在明文攻擊 ( plaintext attacks ) 之下，例如 EAP-IKE2 和 EAP-TTLS。
* 在 EAP 部分使用 PEAPv1 的方法有可能受到中間人攻擊 ( Man-in-the-Middle Attack, MitM Attack )，是因為 PEAPv1 的安全性會需要滿足兩個關鍵要求，分別是:
	1. 客戶端必需驗證服務端的 certificate
	2. 內部受保護的認證方法不得攻擊者可察覺到的形式在 PEAP 之外使用	 
	
	以上若是有任何一點不滿足，就可能遭受中間人攻擊，此外，EAP-TTLS 也同樣可能遭受中間人攻擊

**預防措施：**
* 使用 PEAPv2 修正了原本 PEAPv1 的漏洞，可避免中間人攻擊
* 選擇更高強度的密鑰並提高更換密碼的頻率
* Cisco 建議不要使用有離線密碼破解問題的 LEAP，而是改用 EAP-FAST 以提升安全性。EAP-FAST 保留了原本 LEAP 輕量的優點，且使用另一種身分驗證方式來避免原本離線密碼破解的問題。

#### WPA（Wi-Fi Protected Access, Wi-Fi存取保護）
**漏洞：**
* 弱密碼 ( Weak password )
	WPA 和 WPA2 使用預共享密鑰來進行認證，若使用者使用較弱的密碼或金鑰，就容易遭受密碼破解 ( password cracking ) 攻擊。
* 缺少前向的保密性 ( Lack of forward secrecy )	
	在 WPA 協議中，若是預共享密鑰遭到洩漏，則透過此預共享密鑰可解密未來及過去所有使用該密鑰加密的封包
* WPA 封包的的欺騙和解密 ( WPA packet spoofing and decryption )
	在 WPA-TKIP 協議中，可透過注入一定程度數量的封包以劫持一個 TCP connection，並可在受害者訪問網站時注入惡意的 javascript 檔案
* 金鑰重新安裝攻擊 ( Key Reinstallation Attack, KRACK ）
	金鑰重新安裝攻擊是一個攻擊 WPA 及 WPA2 的方式。WPA2 在四向握手過程中，由於協議中並未要求重新連接的密鑰須不同，因此攻擊者可重新發送其他裝置在溝通時的連接值，並可重置負責創建加密密鑰的初始化向量，使他們可以解密並篡改來自和進入設備的信息。
* 龍血攻擊 ( Dragonblood attack )
	WPA3 的設計瑕疵使攻擊者可以進行降維攻擊 (  downgrade attacks ) 及旁通道攻擊 ( side-channel attack )，來進行對密碼的破解及Wi-Fi基地站的阻斷服務攻擊 ( denial-of-service attack )
	降維攻擊: 也稱為 bidding-down attack 或 version rollback attack，是對通訊協議的加密攻擊，其促使系統放棄較為可靠的模式，轉而使用較舊較不可靠的方法，這通常是協議為了兼容舊版本系統而導致的。
	
**預防措施：**
* 避免使用 WPA-TKIP 以免遭受封包的的欺騙和解密
* 為解決前向的保密性問題，可改使用 WPA3，此協議限制猜測密碼的時間，可避免密碼被暴力破解
* 針對金鑰重新安裝攻擊可透過安裝軟體修補程式來避免，但不是所有的裝置都能適用，目前此問題 WPA3以解決。 WPA3 有新的握手程序，Dragonfly Handshake，取代了 WPA2 的 4 向交握（4-Way Handshake），讓駭客更難破解網路密碼，並使 KRACK 無效。

## 網頁介面
### web介面技術
我們的後端是由 php 實作，並透過其中與 mysql 有關的函數與資料庫互動。我們需要從資料庫獲取的資訊包括使用者的帳號密碼、使用流量與使用時間的資訊。
 
前端則以 HTML 混合 Javascript 來構造網頁，而 style 的部分則是直接在 HTML 的 header 中定義。主要的架構有 header, body, footer, 和 login form，分別利用 PHP function 來包裝。其中 header 主要定義此網頁的 ```<head>``` 內容，包含 global variable 以及 Javascript function。

另外，我們使用 Get 和 Post 的方法得到 user input。在```login.php```以及```register.php```裡面有很多 html form 會送 request，在 php 的部分則是使用 $_GET[parameter] 的結果來得到使用者的輸入。另外，我們也實作了多個 ```<button>```，按了之後會執行 javascript ```window.location.assign("register.php")```來跳轉至其他 php 檔。

### 網頁運作方式

使用者連上網路後，首先會進入```hotspotlogin.php```的頁面，依據不同使用者的操作，```hotspotlogin.php```會導到```login.php```, ```logout.php```, ```register.php```。
1. ```register.php```：將使用者加入 radcheck 和 radusergroup 這兩張 table。
    a. 連上資料庫：
    ```
    $db = mysqli_connect("localhost", "radius", "radpass", "radius");
    ```
    b. 將使用者加入對應的表格：
    ```
    $sql = "insert into radcheck (username,attribute,op,value) values ('$myusername','Cleartext-Password',':=','$mypassword')";
    $limit1 = "insert into radcheck (username, attribute, op, value) values ('$myusername', 'Max-Hourly-Traffic', ':=', '5000000')";
    $limit2 = "insert into radcheck (username, attribute, op, value) values ('$myusername', 'Acct-Interim-Interval', ':=', '60')";
    $limit3 = "insert into radcheck (username, attribute, op, value) values ('$myusername', 'Max-Daily-Session', ':=', '10')";
    ```
    其中，我們預設了 3 個限制，第一個```Max-Hourly-Traffic```代表該使用者在一個小時之內最多使用多少 bytes，第二個```Acct-Interim-Interval```代表每經過多少秒會更新一次使用者的使用時間和使用流量，而```Max-Daily-Session```代表使用者一天可以用多久。這些值之後都會用到。
    ```
    $sql = "insert into radusergroup (username,groupname) values ('$myusername','user')";
    ```
2. ```login.php```：檢查使用者之前有沒有註冊過，若無，重新導回一開始的頁面，若有，讓使用者連上網路。
    a. 檢查使用者有沒有在```radcheck```裡
    ```
    $myusername = mysqli_real_escape_string($db, $_POST['username']);
    $mypassword = mysqli_real_escape_string($db, $_POST['password']);

    $sql = "SELECT * FROM radcheck WHERE username='$myusername' and value='$mypassword'";
    ```
3. ```logout.php```：使用```session_destroy()```關掉 sessionc.後，重新導向至 ```login.php```。

如果想要檢視及編輯每個使用者可以使用的時間與流量的話，可以透過```real_admin.php```。

4. ```real_admin.php```：顯示每個使用者當前可使用時間與可使用流量。
    a. 取得所有的使用者：
    ```
    SELECT distinct(username) FROM radcheck
    ```
    b. 取得個別使用者的可使用時間與可使用流量：
    ```
    SELECT * FROM radcheck WHERE username=$tmp_user_name
    ```
如果按下 edit 鍵，則重新導向至```real_admin_edit.php```。
    
5. ```real_admin_edit.php```：更新資料庫裡被選定的使用者其可使用時間與可使用流量。
    a. 更新資料庫：
    ```
    UPDATE radius.radcheck SET value='$MHFLimit' WHERE radcheck.username='$username' and attribute='Max-Hourly-Traffic'
    ```

#### 超過時間或流量則踢掉使用者
修改```/etc/freeradius/sites-enabled/default```的 authorize 一節，插入：
```
// 控制流量
if ("%{sql: SELECT SUM(acctinputoctets+acctoutputoctets) FROM radacct WHERE username='%{User-Name}' AND acctstarttime >= date_add(current_date, INTERVAL -1 HOUR);}" >= "%{sql: SELECT value FROM radcheck WHERE username='%{User-Name}' AND attribute='Max-Hourly-Traffic';}") {
	reject
}
// 控制時間
if ("%{sql: SELECT SUM(acctstoptime - acctstarttime) FROM radacct WHERE username='%{User-Name}' AND acctstarttime >= date_add(current_date, INTERVAL -1 DAY);}" >= "%{sql: SELECT value FROM radcheck WHERE username='%{User-Name}' AND attribute='Max-Daily-Session';}") {
	reject
}
```

## 貢獻度
全員貢獻度皆為 $\frac{1}{6}$。

## Reference
1. https://www.itread01.com/content/1546818514.html
2. https://github.com/sycLin/CNLab-Lab2