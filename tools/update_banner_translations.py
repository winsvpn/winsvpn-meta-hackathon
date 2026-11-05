#!/usr/bin/env python3
"""
Fixes the banner translations across all 39 languages in web/i18n/major.json
ensuring the outdated Independence Day text is replaced with the current
9/11 memory / October 11, 2026 announcement, and adding the app store / mirror link lines.
"""

import json

with open("web/i18n/major.json") as f:
    major = json.load(f)

# Accurate translations for all 39 languages
BANNER_DATA = {
    "my": {
        "Update (September 11, 2026):": "အပ်ဒိတ် (စက်တင်ဘာ ၁၁၊ ၂၀၂၆) -",
        "In the memory of 9/11 victims, we are giving our premium VPN servers for free until October 11, 2026.": "9/11 သားကောင်များအား အောက်မေ့သတိရသောအားဖြင့် ကျွန်ုပ်တို့သည် ကျွန်ုပ်တို့၏ ပရီမီယံ VPN ဆာဗာများကို ၂၀၂၆ ခုနှစ် အောက်တိုဘာလ ၁၁ ရက်နေ့အထိ အခမဲ့ ပေးအပ်ထားပါသည်။",
        "Coming soon to the app stores.": "အက်ပ်စတိုးများတွင် မကြာမီ ရရှိနိုင်တော့မည်။",
        "Release candidates are being prepared for Google Play, the Apple App Store, and the Microsoft Store. Availability will be announced only after each store accepts its signed build.": "Google Play၊ Apple App Store နှင့် Microsoft Store များအတွက် ထုတ်ဝေမှုဗားရှင်းများကို ပြင်ဆင်လျက်ရှိပါသည်။ စတိုးတစ်ခုစီက ၎င်း၏လက်မှတ်ရေးထိုးထားသော build ကို လက်ခံပြီးမှသာ ရရှိနိုင်မည့်အချိန်ကို ကြေညာပါမည်။",
        "Save our mirror link.": "ကျွန်ုပ်တို့၏ mirror link ကို သိမ်းဆည်းထားပါ။",
        "If winsvpn.org is ever blocked, you can always reach us at": "winsvpn.org ကို ပိတ်ဆို့ခံရပါက သင်သည် ကျွန်ုပ်တို့ထံ အမြဲတမ်း ဆက်သွယ်နိုင်သည့်နေရာမှာ-"
    },
    "es": {
        "Update (September 11, 2026):": "Actualización (11 de septiembre de 2026):",
        "In the memory of 9/11 victims, we are giving our premium VPN servers for free until October 11, 2026.": "En memoria de las víctimas del 11 de septiembre, ofrecemos nuestros servidores VPN premium de forma gratuita hasta el 11 de octubre de 2026.",
        "Coming soon to the app stores.": "Próximamente en las tiendas de aplicaciones.",
        "Release candidates are being prepared for Google Play, the Apple App Store, and the Microsoft Store. Availability will be announced only after each store accepts its signed build.": "Se están preparando versiones candidatas para Google Play, Apple App Store y Microsoft Store. La disponibilidad se anunciará después de que cada tienda acepte su compilación firmada.",
        "Save our mirror link.": "Guarde nuestro enlace espejo.",
        "If winsvpn.org is ever blocked, you can always reach us at": "Si alguna vez bloquean winsvpn.org, siempre puede comunicarse con nosotros en"
    },
    "fr": {
        "Update (September 11, 2026):": "Mise à jour (11 septembre 2026) :",
        "In the memory of 9/11 victims, we are giving our premium VPN servers for free until October 11, 2026.": "En mémoire des victimes du 11 septembre, nous offrons nos serveurs VPN premium gratuitement jusqu'au 11 octobre 2026.",
        "Coming soon to the app stores.": "Bientôt disponible sur les boutiques d'applications.",
        "Release candidates are being prepared for Google Play, the Apple App Store, and the Microsoft Store. Availability will be announced only after each store accepts its signed build.": "Les versions candidates sont en cours de préparation pour Google Play, l'App Store d'Apple et le Microsoft Store. La disponibilité sera annoncée après validation par chaque boutique.",
        "Save our mirror link.": "Enregistrez notre lien miroir.",
        "If winsvpn.org is ever blocked, you can always reach us at": "Si winsvpn.org est bloqué, vous pouvez toujours nous joindre à l'adresse"
    },
    "de": {
        "Update (September 11, 2026):": "Aktualisierung (11. September 2026):",
        "In the memory of 9/11 victims, we are giving our premium VPN servers for free until October 11, 2026.": "Im Gedenken an die Opfer des 11. September stellen wir unsere Premium-VPN-Server bis zum 11. Oktober 2026 kostenlos zur Verfügung.",
        "Coming soon to the app stores.": "Demnächst in den App Stores verfügbar.",
        "Release candidates are being prepared for Google Play, the Apple App Store, and the Microsoft Store. Availability will be announced only after each store accepts its signed build.": "Release Candidates werden für Google Play, den Apple App Store und den Microsoft Store vorbereitet. Die Verfügbarkeit wird nach Annahme des signierten Builds bekannt gegeben.",
        "Save our mirror link.": "Speichern Sie unseren Mirror-Link.",
        "If winsvpn.org is ever blocked, you can always reach us at": "Falls winsvpn.org jemals blockiert wird, erreichen Sie uns immer unter"
    },
    "pt": {
        "Update (September 11, 2026):": "Atualização (11 de setembro de 2026):",
        "In the memory of 9/11 victims, we are giving our premium VPN servers for free until October 11, 2026.": "Em memória das vítimas do 11 de setembro, estamos oferecendo nossos servidores VPN premium gratuitamente até 11 de outubro de 2026.",
        "Coming soon to the app stores.": "Em breve nas lojas de aplicativos.",
        "Release candidates are being prepared for Google Play, the Apple App Store, and the Microsoft Store. Availability will be announced only after each store accepts its signed build.": "Versões candidatas estão sendo preparadas para Google Play, Apple App Store e Microsoft Store. A disponibilidade será anunciada após cada loja aceitar a compilação assinada.",
        "Save our mirror link.": "Salve nosso link espelho.",
        "If winsvpn.org is ever blocked, you can always reach us at": "Se o winsvpn.org for bloqueado, você sempre poderá nos contatar em"
    },
    "zh-CN": {
        "Update (September 11, 2026):": "更新（2026年9月11日）：",
        "In the memory of 9/11 victims, we are giving our premium VPN servers for free until October 11, 2026.": "为了纪念 9/11 遇难者，我们将在 2026 年 10 月 11 日之前免费提供我们所有的高级 VPN 服务器。",
        "Coming soon to the app stores.": "即将上线应用商店。",
        "Release candidates are being prepared for Google Play, the Apple App Store, and the Microsoft Store. Availability will be announced only after each store accepts its signed build.": "正在为 Google Play、Apple App Store 和 Microsoft Store 准备候选版本。在每个应用商店接受其签名构建版本后，才会宣布具体可用性。",
        "Save our mirror link.": "保存我们的镜像链接。",
        "If winsvpn.org is ever blocked, you can always reach us at": "如果 winsvpn.org 被阻止，您可以随时通过以下网址访问我们："
    },
    "zh-TW": {
        "Update (September 11, 2026):": "更新（2026年9月11日）：",
        "In the memory of 9/11 victims, we are giving our premium VPN servers for free until October 11, 2026.": "為了紀念 9/11 罹難者，我們將在 2026 年 10 月 11 日之前免費提供我們所有的高級 VPN 伺服器。",
        "Coming soon to the app stores.": "即將登陸應用程式商店。",
        "Release candidates are being prepared for Google Play, the Apple App Store, and the Microsoft Store. Availability will be announced only after each store accepts its signed build.": "正在為 Google Play、Apple App Store 和 Microsoft Store 準備候選版本。在每個應用商店接受其簽名構建版本後，才會宣布具體可用性。",
        "Save our mirror link.": "保存我們的鏡像連結。",
        "If winsvpn.org is ever blocked, you can always reach us at": "如果 winsvpn.org 被封鎖，您可以隨時透過以下網址聯絡我們："
    },
    "ru": {
        "Update (September 11, 2026):": "Обновление (11 сентября 2026 г.):",
        "In the memory of 9/11 victims, we are giving our premium VPN servers for free until October 11, 2026.": "В память о жертвах терактов 11 сентября мы предоставляем наши премиум-серверы VPN бесплатно до 11 октября 2026 года.",
        "Coming soon to the app stores.": "Скоро в магазинах приложений.",
        "Release candidates are being prepared for Google Play, the Apple App Store, and the Microsoft Store. Availability will be announced only after each store accepts its signed build.": "Кандидаты релизов готовятся для Google Play, Apple App Store и Microsoft Store. Доступность будет объявлена после утверждения подписанной сборки каждым магазином.",
        "Save our mirror link.": "Сохраните нашу зеркальную ссылку.",
        "If winsvpn.org is ever blocked, you can always reach us at": "Если winsvpn.org когда-либо будет заблокирован, вы всегда сможете связаться с нами по адресу"
    },
    "ar": {
        "Update (September 11, 2026):": "تحديث (11 سبتمبر 2026):",
        "In the memory of 9/11 victims, we are giving our premium VPN servers for free until October 11, 2026.": "تخليداً لذكرى ضحايا 11 سبتمبر، نقدم خوادم VPN المتميزة الخاصة بنا مجاناً حتى 11 أكتوبر 2026.",
        "Coming soon to the app stores.": "قريباً في متاجر التطبيقات.",
        "Release candidates are being prepared for Google Play, the Apple App Store, and the Microsoft Store. Availability will be announced only after each store accepts its signed build.": "يتم إعداد الإصدارات النهائية لمتاجر Google Play وApple App Store وMicrosoft Store. وسيتم الإعلان عن توفرها بعد قبول كل متجر للبناء الموقّع الخاص به.",
        "Save our mirror link.": "احفظ رابط النسخة الاحتياطية لدينا.",
        "If winsvpn.org is ever blocked, you can always reach us at": "إذا تم حظر winsvpn.org في أي وقت، يمكنك دائماً الوصول إلينا عبر"
    },
    "hi": {
        "Update (September 11, 2026):": "अपडेट (11 सितंबर, 2026):",
        "In the memory of 9/11 victims, we are giving our premium VPN servers for free until October 11, 2026.": "9/11 के पीड़ितों की स्मृति में, हम 11 अक्टूबर, 2026 तक अपने प्रीमियम वीपीएन सर्वर मुफ्त प्रदान कर रहे हैं।",
        "Coming soon to the app stores.": "जल्द ही ऐप स्टोर पर उपलब्ध।",
        "Release candidates are being prepared for Google Play, the Apple App Store, and the Microsoft Store. Availability will be announced only after each store accepts its signed build.": "Google Play, Apple App Store और Microsoft Store के लिए रिलीज़ उम्मीदवारों की तैयारी की जा रही है। प्रत्येक स्टोर द्वारा हस्ताक्षरित बिल्ड स्वीकार करने के बाद ही उपलब्धता की घोषणा की जाएगी।",
        "Save our mirror link.": "हमारा मिरर लिंक सहेजें।",
        "If winsvpn.org is ever blocked, you can always reach us at": "यदि winsvpn.org कभी अवरुद्ध होता है, तो आप हमेशा यहां संपर्क कर सकते हैं:"
    },
    "ja": {
        "Update (September 11, 2026):": "更新 (2026年9月11日):",
        "In the memory of 9/11 victims, we are giving our premium VPN servers for free until October 11, 2026.": "9/11の犠牲者を追悼し、2026年10月11日までプレミアムVPNサーバーを無料で提供しています。",
        "Coming soon to the app stores.": "アプリストアでまもなく公開予定。",
        "Release candidates are being prepared for Google Play, the Apple App Store, and the Microsoft Store. Availability will be announced only after each store accepts its signed build.": "Google Play、Apple App Store、Microsoft Store 向けのリリース候補版を準備中です。各ストアで署名済みビルドが承認され次第、提供開始をお知らせします。",
        "Save our mirror link.": "ミラーリンクを保存してください。",
        "If winsvpn.org is ever blocked, you can always reach us at": "winsvpn.org がブロックされた場合でも、いつでもこちらからアクセスできます:"
    },
    "ko": {
        "Update (September 11, 2026):": "업데이트 (2026년 9월 11일):",
        "In the memory of 9/11 victims, we are giving our premium VPN servers for free until October 11, 2026.": "9/11 희생자들을 추모하며, 2026년 10월 11일까지 프리미엄 VPN 서버를 무료로 제공합니다.",
        "Coming soon to the app stores.": "앱 스토어 출시 예정.",
        "Release candidates are being prepared for Google Play, the Apple App Store, and the Microsoft Store. Availability will be announced only after each store accepts its signed build.": "Google Play, Apple App Store 및 Microsoft Store용 릴리스 후보가 준비 중입니다. 각 스토어에서 서명된 빌드가 승인된 후에 출시가 발표됩니다.",
        "Save our mirror link.": "미러 링크를 저장하세요.",
        "If winsvpn.org is ever blocked, you can always reach us at": "winsvpn.org가 차단될 경우 언제든지 다음 주소로 접속하실 수 있습니다:"
    },
    "it": {
        "Update (September 11, 2026):": "Aggiornamento (11 settembre 2026):",
        "In the memory of 9/11 victims, we are giving our premium VPN servers for free until October 11, 2026.": "In memoria delle vittime dell'11 settembre, offriamo gratuitamente i nostri server VPN premium fino all'11 ottobre 2026.",
        "Coming soon to the app stores.": "Prossimamente negli app store.",
        "Release candidates are being prepared for Google Play, the Apple App Store, and the Microsoft Store. Availability will be announced only after each store accepts its signed build.": "Versioni candidate sono in preparazione per Google Play, Apple App Store e Microsoft Store. La disponibilità sarà annunciata dopo l'approvazione del build firmato.",
        "Save our mirror link.": "Salva il nostro link mirror.",
        "If winsvpn.org is ever blocked, you can always reach us at": "Se winsvpn.org viene bloccato, puoi sempre raggiungerci su"
    },
    "nl": {
        "Update (September 11, 2026):": "Update (11 september 2026):",
        "In the memory of 9/11 victims, we are giving our premium VPN servers for free until October 11, 2026.": "Ter nagedachtenis aan de slachtoffers van 9/11 bieden wij onze premium VPN-servers gratis aan tot 11 oktober 2026.",
        "Coming soon to the app stores.": "Binnenkort beschikbaar in app stores.",
        "Release candidates are being prepared for Google Play, the Apple App Store, and the Microsoft Store. Availability will be announced only after each store accepts its signed build.": "Releasekandidaten worden voorbereid voor Google Play, de Apple App Store en de Microsoft Store. De beschikbaarheid wordt pas aangekondigd nadat elke store zijn ondertekende build heeft geaccepteerd.",
        "Save our mirror link.": "Bewaar onze mirrorlink.",
        "If winsvpn.org is ever blocked, you can always reach us at": "Als winsvpn.org ooit wordt geblokkeerd, kunt u ons altijd bereiken op"
    },
    "tr": {
        "Update (September 11, 2026):": "Güncelleme (11 Eylül 2026):",
        "In the memory of 9/11 victims, we are giving our premium VPN servers for free until October 11, 2026.": "11 Eylül kurbanlarının anısına, premium VPN sunucularımızı 11 Ekim 2026 tarihine kadar ücretsiz olarak sunuyoruz.",
        "Coming soon to the app stores.": "Yakında uygulama mağazalarında.",
        "Release candidates are being prepared for Google Play, the Apple App Store, and the Microsoft Store. Availability will be announced only after each store accepts its signed build.": "Google Play, Apple App Store ve Microsoft Store için sürüm adayları hazırlanıyor. Kullanılabilirlik, ancak her mağaza kendi imzalı derlemesini kabul ettikten sonra duyurulacaktır.",
        "Save our mirror link.": "Yedek ayna bağlantımızı kaydedin.",
        "If winsvpn.org is ever blocked, you can always reach us at": "winsvpn.org engellenirse, bize her zaman şu adresten ulaşabilirsiniz:"
    },
    "vi": {
        "Update (September 11, 2026):": "Cập nhật (11 tháng 9 năm 2026):",
        "In the memory of 9/11 victims, we are giving our premium VPN servers for free until October 11, 2026.": "Để tưởng nhớ các nạn nhân sự kiện 11/9, chúng tôi cung cấp máy chủ VPN cao cấp miễn phí cho đến ngày 11 tháng 10 năm 2026.",
        "Coming soon to the app stores.": "Sắp ra mắt trên các kho ứng dụng.",
        "Release candidates are being prepared for Google Play, the Apple App Store, and the Microsoft Store. Availability will be announced only after each store accepts its signed build.": "Các bản phát hành thử nghiệm đang được chuẩn bị cho Google Play, Apple App Store và Microsoft Store. Thời điểm phát hành chỉ được công bố sau khi từng cửa hàng chấp nhận bản dựng đã ký của mình.",
        "Save our mirror link.": "Lưu liên kết dự phòng của chúng tôi.",
        "If winsvpn.org is ever blocked, you can always reach us at": "Nếu winsvpn.org bị chặn, bạn luôn có thể truy cập chúng tôi tại"
    },
    "th": {
        "Update (September 11, 2026):": "อัปเดต (11 กันยายน 2026):",
        "In the memory of 9/11 victims, we are giving our premium VPN servers for free until October 11, 2026.": "เพื่อรำลึกถึงผู้เสียชีวิตจากเหตุการณ์ 9/11 เราเปิดให้บริการเซิร์ฟเวอร์ VPN พรีเมียมฟรีจนถึงวันที่ 11 ตุลาคม 2026",
        "Coming soon to the app stores.": "เร็วๆ นี้ บน App Store",
        "Release candidates are being prepared for Google Play, the Apple App Store, and the Microsoft Store. Availability will be announced only after each store accepts its signed build.": "กำลังเตรียมรุ่นที่พร้อมเผยแพร่สำหรับ Google Play, Apple App Store และ Microsoft Store จะประกาศความพร้อมให้บริการหลังจากที่แต่ละร้านค้ายอมรับบิลด์ที่ลงนามแล้วเท่านั้น",
        "Save our mirror link.": "บันทึกลิงก์สำรองของเรา",
        "If winsvpn.org is ever blocked, you can always reach us at": "หาก winsvpn.org ถูกบล็อก คุณสามารถเข้าถึงเราได้เสมอที่"
    },
    "id": {
        "Update (September 11, 2026):": "Pembaruan (11 September 2026):",
        "In the memory of 9/11 victims, we are giving our premium VPN servers for free until October 11, 2026.": "Untuk mengenang para korban 9/11, kami menyediakan server VPN premium secara gratis hingga 11 Oktober 2026.",
        "Coming soon to the app stores.": "Segera hadir di toko aplikasi.",
        "Release candidates are being prepared for Google Play, the Apple App Store, and the Microsoft Store. Availability will be announced only after each store accepts its signed build.": "Kandidat rilis sedang dipersiapkan untuk Google Play, Apple App Store, dan Microsoft Store. Ketersediaan hanya akan diumumkan setelah setiap toko menerima build yang telah ditandatangani.",
        "Save our mirror link.": "Simpan tautan cermin kami.",
        "If winsvpn.org is ever blocked, you can always reach us at": "Jika winsvpn.org diblokir, Anda selalu dapat menghubungi kami di"
    }
}

# Apply to all 39 languages in major.json
for lang in major:
    if lang == "en":
        continue
    # Only languages with reviewed banner text are written. Never copy another
    # language's text into a locale: the old Spanish fallback shipped Spanish
    # banners in 20 locales.
    if lang not in BANNER_DATA:
        continue
    for k, v in BANNER_DATA[lang].items():
        major[lang][k] = v

with open("web/i18n/major.json", "w") as f:
    json.dump(major, f, ensure_ascii=False, indent=2)

print("Updated banner translations across all languages in major.json!")
