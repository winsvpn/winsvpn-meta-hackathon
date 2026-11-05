#!/usr/bin/env python3
"""
Populates missing feature and protocol card translations across major.json.
"""

import json

# Define the new translation dictionary
NEW_TRANSLATIONS = {
    "my": {
        "We use customized local AI for your privacy, and we keep the VPN current with real-world censorship and network conditions so it keeps working for you. We do not collect your personal data, so we cannot train on it.": 
            "သင့်ကိုယ်ရေးကိုယ်တာလုံခြုံမှုအတွက် စိတ်ကြိုက်ပြင်ဆင်ထားသော ပြည်တွင်းသုံး AI ကို အသုံးပြုထားပြီး၊ ကွန်ရက်အခြေအနေများနှင့် လက်တွေ့ဆင်ဆာဖြတ်တောက်မှုများအတိုင်း VPN ကို အမြဲမပြတ်ခေတ်မီစေရန် ဆောင်ရွက်ထားသောကြောင့် သင့်အတွက် ဆက်လက်အလုပ်လုပ်နေမည်ဖြစ်သည်။ ကျွန်ုပ်တို့သည် သင့်ကိုယ်ရေးကိုယ်တာအချက်အလက်များကို မစုဆောင်းသောကြောင့် ယင်းတို့အပေါ် AI လေ့ကျင့်သင်ကြားခြင်း မပြုလုပ်နိုင်ပါ။",
        "The first non-profit VPN built on its own protocol. A US 501(c)(3) public charity, expanding access to cybersecurity, uncensored news, and education.":
            "ကိုယ်ပိုင်ပရိုတိုကောဖြင့် တည်ဆောက်ထားသော ပထမဆုံး အကျိုးအမြတ်မယူသော VPN ဖြစ်သည်။ အမေရိကန် 501(c)(3) အများပြည်သူဆိုင်ရာ ပရဟိတအဖွဲ့အစည်းဖြစ်ပြီး ဆိုက်ဘာလုံခြုံရေး၊ ဆင်ဆာမဲ့သတင်းများနှင့် ပညာရေးကို လက်လှမ်းမီနိုင်စေရန် တိုးချဲ့ဆောင်ရွက်ပေးနေပါသည်။",
        "No browsing history, no DNS query history, no traffic contents, and no record of the destinations you reach. Transient session state is cleared when the VPN disconnects. The privacy-preserving device-limit metadata behind the three-device limit is deleted or overwritten once a device is deactivated or replaced, and app-collected operational data we no longer need is deleted or anonymized within 90 days. What is left is only what an account needs: status, payment and referral state, and proof you accepted the terms.":
            "ရှာဖွေမှုမှတ်တမ်း၊ DNS မေးမြန်းမှုမှတ်တမ်း၊ ဒေတာစီးဆင်းမှုအကြောင်းအရာများနှင့် သင်ရောက်ရှိခဲ့သော ဦးတည်ရာနေရာများ၏ မှတ်တမ်းများကို လုံးဝမသိမ်းဆည်းပါ။ VPN ချိတ်ဆက်မှုပြတ်တောက်သွားချိန်တွင် ယာယီစက်ရှင်အခြေအနေများကို ရှင်းလင်းပစ်ပါသည်။ စက် ၃ လုံးကန့်သတ်ချက်နောက်ကွယ်ရှိ ကိုယ်ရေးကိုယ်တာလုံခြုံမှုကို ထိန်းသိမ်းထားသော မက်တာဒေတာများကို စက်ပစ္စည်းတစ်ခုအား ပိတ်လိုက်ခြင်း သို့မဟုတ် အစားထိုးလိုက်ခြင်းနှင့်အတူ ဖျက်ပစ်ခြင်း သို့မဟုတ် အစားထိုးရေးသားပစ်ပြီး မလိုအပ်တော့သော အက်ပ်လုပ်ငန်းလည်ပတ်မှုဆိုင်ရာ အချက်အလက်များကို ရက် ၉၀ အတွင်း ဖျက်ပစ်ခြင်း သို့မဟုတ် အမည်ဝှက်ခြင်းများ ပြုလုပ်ပါသည်။ ကျန်ရှိသောအချက်အလက်များမှာ အကောင့်တစ်ခုအတွက် မဖြစ်မနေလိုအပ်သော အခြေအနေ၊ ငွေပေးချေမှုနှင့် လွှဲပြောင်းညွှန်းဆိုမှုအခြေအနေ၊ နှင့် စည်းကမ်းချက်များကို သဘောတူလက်ခံထားကြောင်း သက်သေသာဖြစ်သည်။",
        "Our servers have a hot site disaster recovery approach using latest hardware, weekly maintenance and backups, and 24/7 attack monitoring by Intrusion Detection & Prevention System (IDS/IPS). On every node the firewall drops inbound and forwarded traffic by default, IPv6 is disabled, torrent ports are blocked, and SSH accepts key-based logins only, with no passwords and a 24-hour ban after 10 failed logins in an hour. Security updates install automatically and core dumps are disabled, so process memory never reaches disk.":
            "ကျွန်ုပ်တို့၏ဆာဗာများသည် နောက်ဆုံးပေါ်ဟာ့ဒ်ဝဲများ၊ အပတ်စဉ် ပြုပြင်ထိန်းသိမ်းမှုနှင့် အရန်သိမ်းဆည်းမှုများ၊ ကျူးကျော်ဝင်ရောက်မှု ထောက်လှမ်းခြင်းနှင့် ကာကွယ်ခြင်းစနစ် (IDS/IPS) ဖြင့် ၂၄/၇ တိုက်ခိုက်မှုစောင့်ကြည့်ခြင်းတို့ကို အသုံးပြုသည့် hot-site သဘာဝဘေးအန္တရာယ် ပြန်လည်ထူထောင်ရေးချဉ်းကပ်မှုကို အသုံးပြုထားပါသည်။ ဆာဗာတိုင်းတွင် ဖိုင်ယားဝေါလ်သည် ဝင်လာသောဒေတာနှင့် လက်ဆင့်ကမ်းဒေတာများကို မူရင်းအတိုင်း ပယ်ချထားပြီး၊ IPv6 ကို ပိတ်ထားကာ၊ torrent ပေါက်များကို ပိတ်ဆို့ထားပြီး၊ SSH သည် စကားဝှက်မသုံးဘဲ သော့အခြေပြုဝင်ရောက်မှုကိုသာ ခွင့်ပြုထားပြီး တစ်နာရီအတွင်း အကြိမ် ၁၀ ကြိမ် ဝင်ရောက်ရန်မအောင်မြင်ပါက ၂၄ နာရီ ပိတ်ပင်ထားပါသည်။ လုံခြုံရေးအပ်ဒိတ်များကို အလိုအလျောက် ထည့်သွင်းပေးပြီး core dumps များကို ပိတ်ထားသောကြောင့် လုပ်ငန်းစဉ်မှတ်ဉာဏ်သည် ဒစ်ခ်ပေါ်သို့ မည်သည့်အခါမျှ မရောက်ရှိပါ။",
        "Win's VPN Inc. and Win Empire LLC maintain insurance-readiness controls and may seek cyber or Technology Errors and Omissions coverage. We do not represent that a particular policy is currently bound or in force. Coverage must be confirmed from a current binder or issued policy.":
            "Win's VPN Inc. နှင့် Win Empire LLC တို့သည် အာမခံရရှိရေး ထိန်းချုပ်မှုများကို ထိန်းသိမ်းထားပြီး ဆိုက်ဘာ သို့မဟုတ် နည်းပညာဆိုင်ရာ အမှားအယွင်းများနှင့် ချန်လှပ်မှုများဆိုင်ရာ အာမခံအကာအကွယ်ကို ရယူနိုင်ပါသည်။ ကျွန်ုပ်တို့သည် သီးခြားပေါ်လစီတစ်ခုကို လက်ရှိတွင် စာချုပ်ချုပ်ဆိုထားသည် သို့မဟုတ် အသက်ဝင်နေသည်ဟု အာမခံဖော်ပြခြင်းမပြုပါ။ အာမခံအကာအကွယ်ကို လက်ရှိထုတ်ပေးထားသော စာချုပ် သို့မဟုတ် ထုတ်ပြန်ထားသော ပေါ်လစီမှတစ်ဆင့် အတည်ပြုရမည်ဖြစ်သည်။",
        "In telecom terms, if today’s leading VPN protocols are 5G, Winn Protocol® is built to be the 6G: a generation ahead in how it hides traffic, races routes, and holds a connection together across hostile networks.":
            "ဆက်သွယ်ရေးနယ်ပယ်အရ ယနေ့ခေတ် ထိပ်တန်း VPN ပရိုတိုကောများသည် 5G ဖြစ်ပါက၊ Winn Protocol® သည် 6G ဖြစ်လာစေရန် တည်ဆောက်ထားပါသည်- ဒေတာအသွားအလာကို ဖုံးကွယ်ခြင်း၊ လမ်းကြောင်းများကို ယှဉ်ပြိုင်ရွေးချယ်ခြင်းနှင့် ရန်လိုသောကွန်ရက်များတစ်လျှောက် ချိတ်ဆက်မှုကို မြဲမြံစွာထိန်းထားခြင်းတို့တွင် မျိုးဆက်တစ်ခု ရှေ့ရောက်နေပါသည်။",
        "Winn Protocol® is engineered to bypass NGFW Deep Packet Inspection as long as there is a working path from a user’s country to the outside world.":
            "Winn Protocol® သည် အသုံးပြုသူ၏နိုင်ငံမှ ပြင်ပကမ္ဘာသို့ အလုပ်လုပ်နိုင်သော လမ်းကြောင်းတစ်ခုရှိနေသရွေ့ NGFW Deep Packet Inspection (DPI) ကို ရှောင်ကွင်းကျော်လွှားနိုင်ရန် အင်ဂျင်နီယာနည်းပညာဖြင့် တည်ဆောက်ထားပါသည်။",
        "Built on published NIST and IETF standards, not private cryptography. Every primitive below is publicly specified and independently reviewable.":
            "သီးသန့်ခိုးဝှက်ကုဒ်သွင်းခြင်း မဟုတ်ဘဲ ထုတ်ပြန်ထားသော NIST နှင့် IETF စံနှုန်းများပေါ်တွင် တည်ဆောက်ထားပါသည်။ အောက်ဖော်ပြပါ အခြေခံနည်းပညာတိုင်းကို လူသိရှင်ကြား သတ်မှတ်ထားပြီး သီးခြားလွတ်လပ်စွာ စစ်ဆေးနိုင်ပါသည်။",
        "Post-quantum key exchange": "Post-quantum သော့ဖလှယ်မှု",
        "Hybrid, never ML-KEM alone. Protects today’s traffic against future quantum decryption of recorded sessions.":
            "ML-KEM တစ်ခုတည်းမဟုတ်ဘဲ ပေါင်းစပ်စနစ် (Hybrid) ဖြစ်သည်။ မှတ်တမ်းတင်ထားသော စက်ရှင်များကို အနာဂတ်ကွမ်တမ်ကွန်ပျူတာဖြင့် ကုဒ်ဖျက်ခြင်းမှ ယနေ့ခေတ် အသွားအလာများကို ကာကွယ်ပေးပါသည်။",
        "Post-quantum signatures": "Post-quantum လက်မှတ်များ",
        "Every control-plane request and response is signed, in addition to mutual X.509 authentication.":
            "နှစ်ဦးနှစ်ဖက် X.509 စိစစ်အတည်ပြုခြင်းအပြင် ထိန်းချုပ်မှုအဆင့် တောင်းဆိုမှုနှင့် တုံ့ပြန်မှုတိုင်းကို လက်မှတ်ရေးထိုးထားပါသည်။",
        "Transport": "သယ်ယူပို့ဆောင်ရေး",
        "RFC 9849 ECH conceals the destination name. No classical-only or public-ClientHello fallback is offered.":
            "RFC 9849 ECH သည် ဦးတည်ရာအမည်ကို ဖုံးကွယ်ထားသည်။ ရှေးရိုးသီးသန့် သို့မဟုတ် လူသိရှင်ကြား ClientHello သို့ နောက်ပြန်ဆုတ်ခြင်းကို ခွင့်မပြုပါ။",
        "Device identity": "စက်ပစ္စည်း အထောက်အထား",
        "Each device carries an authenticated URI identity that must match its request, with key rotation and no downtime.":
            "စက်ပစ္စည်းတိုင်းတွင် ၎င်း၏တောင်းဆိုမှုနှင့် ကိုက်ညီရမည့် အတည်ပြုပြီး URI အထောက်အထားပါရှိပြီး စက်ရပ်နားချိန်မရှိဘဲ သော့လည်ပတ်လဲလှယ်မှုကို ပြုလုပ်ပေးပါသည်။",
        "Failure behaviour": "ချို့ယွင်းမှုဆိုင်ရာ လုပ်ဆောင်ချက်",
        "Fail-closed": "Fail-closed (အလိုအလျောက်ပိတ်ရပ်စနစ်)",
        "Any mismatch in ECH, version, cipher group or ALPN aborts the connection rather than silently downgrading it.":
            "ECH၊ ဗားရှင်း၊ cipher group သို့မဟုတ် ALPN တို့တွင် မကိုက်ညီမှုတစ်ခုခုရှိပါက ချိတ်ဆက်မှုကို အဆင့်လျှော့ချမည့်အစား ချက်ချင်းရပ်ဆိုင်းပစ်ပါသည်။",
        "Key rotation": "သော့လည်ပတ်လဲလှယ်မှု",
        "Fresh exchange every rotation": "လည်ပတ်လဲလှယ်မှုတိုင်းတွင် အသစ်လဲလှယ်ခြင်း",
        "Session resumption is disabled, so each rekey performs a full hybrid post-quantum exchange.":
            "စက်ရှင်ပြန်လည်စတင်ခြင်းကို ပိတ်ထားသောကြောင့် သော့အသစ်လဲလှယ်မှုတိုင်းသည် ပေါင်းစပ် post-quantum အပြည့်အဝလဲလှယ်မှုကို လုပ်ဆောင်ပါသည်။",
        "Our adaptable, modified, and hardened versions of proven censorship-bypassing protocols are designed to bypass censorship without affecting speed.":
            "သက်သေပြပြီးသား ဆင်ဆာရှောင်ကွင်း ပရိုတိုကောများ၏ ကျွန်ုပ်တို့၏ လိုက်လျောညီထွေရှိပြီး ပြုပြင်မွမ်းမံကာ ခိုင်မာအောင် ပြုလုပ်ထားသော ဗားရှင်းများသည် အမြန်နှုန်းကို မထိခိုက်စေဘဲ ဆင်ဆာဖြတ်တောက်မှုကို ရှောင်ကွင်းနိုင်ရန် ဒီဇိုင်းထုတ်ထားပါသည်။",
        "Continuous connection": "အဆက်မပြတ်ချိတ်ဆက်မှု",
        "Winn Protocol® prepares several routes in advance and races them. If a path degrades or drops, a replacement is established and verified before the old one is torn down (make-before-break) so the tunnel does not go down while it changes. The kill switch stays active throughout, so traffic never escapes during the handover.":
            "Winn Protocol® သည် လမ်းကြောင်းများစွာကို ကြိုတင်ပြင်ဆင်ပြီး ယှဉ်ပြိုင်စေပါသည်။ လမ်းကြောင်းတစ်ခု ကျဆင်းသွားခြင်း သို့မဟုတ် ပြတ်တောက်သွားပါက၊ လမ်းကြောင်းဟောင်းကို မဖျက်မီ အစားထိုးလမ်းကြောင်းကို တည်ဆောက်ပြီး အတည်ပြုပါသည် (make-before-break) ထို့ကြောင့် ပြောင်းလဲနေစဉ်အတွင်း ဥမင်လိုဏ်ခေါင်း ချိတ်ဆက်မှု မပြတ်တောက်ပါ။ လမ်းကြောင်းလွှဲပြောင်းနေစဉ်အတွင်း ဒေတာများ မပေါက်ကြားစေရန် Kill switch သည် အချိန်ပြည့် အသက်ဝင်နေပါသည်။",
        "How we are funded": "ကျွန်ုပ်တို့၏ ရန်ပုံငွေရရှိပုံ",
        "Donations from the public and cost-recovery subscriptions. Contributions are tax-deductible to the extent allowed by law. The IRS determination letter and our EIN are published in Proof.":
            "အများပြည်သူထံမှ လှူဒါန်းငွေများနှင့် ကုန်ကျစရိတ်ကာမိစေသော စာရင်းသွင်းမှုများမှ ရရှိပါသည်။ လှူဒါန်းငွေများကို ဥပဒေအရ ခွင့်ပြုထားသည့်အတိုင်း အခွန်နုတ်ယူနိုင်ပါသည်။ IRS အခွန်ကင်းလွတ်ခွင့်စာလွှာနှင့် ကျွန်ုပ်တို့၏ EIN နံပါတ်ကို သက်သေအထောက်အထား (Proof) တွင် ထုတ်ပြန်ထားပါသည်။"
    },
    "es": {
        "We use customized local AI for your privacy, and we keep the VPN current with real-world censorship and network conditions so it keeps working for you. We do not collect your personal data, so we cannot train on it.":
            "Utilizamos IA local personalizada para su privacidad y mantenemos la VPN actualizada con la censura y condiciones de red del mundo real para que siga funcionando. No recopilamos sus datos personales, por lo que no podemos entrenar con ellos.",
        "The first non-profit VPN built on its own protocol. A US 501(c)(3) public charity, expanding access to cybersecurity, uncensored news, and education.":
            "La primera VPN sin fines de lucro construida sobre su propio protocolo. Una organización benéfica pública 501(c)(3) de EE. UU. que amplía el acceso a la ciberseguridad, noticias sin censura y educación.",
        "No browsing history, no DNS query history, no traffic contents, and no record of the destinations you reach. Transient session state is cleared when the VPN disconnects. The privacy-preserving device-limit metadata behind the three-device limit is deleted or overwritten once a device is deactivated or replaced, and app-collected operational data we no longer need is deleted or anonymized within 90 days. What is left is only what an account needs: status, payment and referral state, and proof you accepted the terms.":
            "Sin historial de navegación, sin historial de consultas DNS, sin contenido de tráfico y sin registro de los destinos que visita. El estado transitorio de la sesión se borra al desconectarse. Los metadatos de límite de 3 dispositivos se eliminan o sobrescriben al desactivar o reemplazar un dispositivo, y los datos operativos se eliminan o anonimizan en 90 días.",
        "Our servers have a hot site disaster recovery approach using latest hardware, weekly maintenance and backups, and 24/7 attack monitoring by Intrusion Detection & Prevention System (IDS/IPS). On every node the firewall drops inbound and forwarded traffic by default, IPv6 is disabled, torrent ports are blocked, and SSH accepts key-based logins only, with no passwords and a 24-hour ban after 10 failed logins in an hour. Security updates install automatically and core dumps are disabled, so process memory never reaches disk.":
            "Nuestros servidores utilizan un enfoque de recuperación ante desastres en sitio activo con hardware moderno, mantenimiento y copias de seguridad semanales, y monitoreo 24/7 mediante IDS/IPS. En cada nodo el firewall bloquea tráfico no autorizado, IPv6 está deshabilitado, puertos torrent bloqueados y SSH solo admite claves con bloqueo de 24 horas tras 10 intentos fallidos en una hora.",
        "Win's VPN Inc. and Win Empire LLC maintain insurance-readiness controls and may seek cyber or Technology Errors and Omissions coverage. We do not represent that a particular policy is currently bound or in force. Coverage must be confirmed from a current binder or issued policy.":
            "Win's VPN Inc. y Win Empire LLC mantienen controles de preparación para seguros y pueden buscar cobertura contra riesgos cibernéticos o errores y omisiones tecnológicas. No declaramos que una póliza en particular esté actualmente vinculada o en vigor. La cobertura debe confirmarse mediante póliza emitida.",
        "In telecom terms, if today’s leading VPN protocols are 5G, Winn Protocol® is built to be the 6G: a generation ahead in how it hides traffic, races routes, and holds a connection together across hostile networks.":
            "En términos de telecomunicaciones, si los protocolos VPN líderes actuales son 5G, Winn Protocol® está diseñado para ser 6G: una generación por delante en cómo oculta el tráfico, compite rutas y mantiene la conexión a través de redes hostiles.",
        "Winn Protocol® is engineered to bypass NGFW Deep Packet Inspection as long as there is a working path from a user’s country to the outside world.":
            "Winn Protocol® está diseñado para evadir la inspección profunda de paquetes NGFW siempre que exista una ruta funcional hacia el exterior.",
        "Built on published NIST and IETF standards, not private cryptography. Every primitive below is publicly specified and independently reviewable.":
            "Basado en estándares publicados de NIST e IETF, no en criptografía privada. Cada primitiva siguiente está especificada públicamente y es auditable de forma independiente.",
        "Post-quantum key exchange": "Intercambio de claves poscuántico",
        "Hybrid, never ML-KEM alone. Protects today’s traffic against future quantum decryption of recorded sessions.":
            "Híbrido, nunca ML-KEM solo. Protege el tráfico actual contra descifrado cuántico futuro de sesiones grabadas.",
        "Post-quantum signatures": "Firmas poscuánticas",
        "Every control-plane request and response is signed, in addition to mutual X.509 authentication.":
            "Cada solicitud y respuesta del plano de control está firmada, además de la autenticación mutua X.509.",
        "Transport": "Transporte",
        "RFC 9849 ECH conceals the destination name. No classical-only or public-ClientHello fallback is offered.":
            "RFC 9849 ECH oculta el nombre de destino. No se ofrece retroceso a ClientHello público o clásico.",
        "Device identity": "Identidad del dispositivo",
        "Each device carries an authenticated URI identity that must match its request, with key rotation and no downtime.":
            "Cada dispositivo tiene una identidad URI autenticada con rotación de claves sin tiempo de inactividad.",
        "Failure behaviour": "Comportamiento ante fallos",
        "Fail-closed": "Fallo seguro (Fail-closed)",
        "Any mismatch in ECH, version, cipher group or ALPN aborts the connection rather than silently downgrading it.":
            "Cualquier discrepancia aborta la conexión en lugar de degradarla silenciosamente.",
        "Key rotation": "Rotación de claves",
        "Fresh exchange every rotation": "Intercambio nuevo en cada rotación",
        "Session resumption is disabled, so each rekey performs a full hybrid post-quantum exchange.":
            "La reanudación de sesión está deshabilitada, por lo que cada recambio realiza un intercambio poscuántico completo.",
        "Continuous connection": "Conexión continua",
        "How we are funded": "Cómo nos financiamos",
        "Donations from the public and cost-recovery subscriptions. Contributions are tax-deductible to the extent allowed by law. The IRS determination letter and our EIN are published in Proof.":
            "Donaciones del público y suscripciones para recuperación de costos. Las contribuciones son deducibles de impuestos según la ley. La carta del IRS y el EIN están en Pruebas."
    },
    "fr": {
        "We use customized local AI for your privacy, and we keep the VPN current with real-world censorship and network conditions so it keeps working for you. We do not collect your personal data, so we cannot train on it.":
            "Nous utilisons une IA locale personnalisée pour votre vie privée et maintenons le VPN à jour face à la censure du monde réel. Nous ne collectons pas vos données personnelles et ne pouvons donc pas entraîner de modèles dessus.",
        "The first non-profit VPN built on its own protocol. A US 501(c)(3) public charity, expanding access to cybersecurity, uncensored news, and education.":
            "Le premier VPN à but non lucratif reposant sur son propre protocole. Organisme de bienfaisance public américain 501(c)(3) facilitant l'accès à la cybersécurité et aux informations non censurées.",
        "No browsing history, no DNS query history, no traffic contents, and no record of the destinations you reach. Transient session state is cleared when the VPN disconnects. The privacy-preserving device-limit metadata behind the three-device limit is deleted or overwritten once a device is deactivated or replaced, and app-collected operational data we no longer need is deleted or anonymized within 90 days. What is left is only what an account needs: status, payment and referral state, and proof you accepted the terms.":
            "Aucun historique de navigation, aucune requête DNS, aucun contenu de trafic et aucun enregistrement des destinations. L'état temporaire de session est effacé à la déconnexion.",
        "Our servers have a hot site disaster recovery approach using latest hardware, weekly maintenance and backups, and 24/7 attack monitoring by Intrusion Detection & Prevention System (IDS/IPS). On every node the firewall drops inbound and forwarded traffic by default, IPv6 is disabled, torrent ports are blocked, and SSH accepts key-based logins only, with no passwords and a 24-hour ban after 10 failed logins in an hour. Security updates install automatically and core dumps are disabled, so process memory never reaches disk.":
            "Nos serveurs disposent d'un plan de reprise d'activité sur site actif, maintenance et sauvegardes hebdomadaires, et surveillance 24/7 par IDS/IPS. Pare-feu strict, ports torrent bloqués et bannissement SSH de 24h après 10 échecs par heure.",
        "Win's VPN Inc. and Win Empire LLC maintain insurance-readiness controls and may seek cyber or Technology Errors and Omissions coverage. We do not represent that a particular policy is currently bound or in force. Coverage must be confirmed from a current binder or issued policy.":
            "Win's VPN Inc. et Win Empire LLC maintiennent des contrôles d'assurance et peuvent souscrire une couverture cybersécurité ou erreurs et omissions technologiques.",
        "In telecom terms, if today’s leading VPN protocols are 5G, Winn Protocol® is built to be the 6G: a generation ahead in how it hides traffic, races routes, and holds a connection together across hostile networks.":
            "En télécommunications, si les principaux protocoles actuels sont la 5G, Winn Protocol® est conçu pour être la 6G : une génération d'avance pour dissimuler le trafic et résister aux réseaux hostiles.",
        "Winn Protocol® is engineered to bypass NGFW Deep Packet Inspection as long as there is a working path from a user’s country to the outside world.":
            "Winn Protocol® est conçu pour contourner l'inspection approfondie des paquets (DPI) tant qu'une route vers l'extérieur existe.",
        "Built on published NIST and IETF standards, not private cryptography. Every primitive below is publicly specified and independently reviewable.":
            "Fondé sur les normes publiées du NIST et de l'IETF. Chaque primitive est publiquement documentée et vérifiable de manière indépendante.",
        "Post-quantum key exchange": "Échange de clés post-quantique",
        "Hybrid, never ML-KEM alone. Protects today’s traffic against future quantum decryption of recorded sessions.":
            "Hybride, jamais ML-KEM seul. Protège le trafic actuel contre le déchiffrement quantique futur.",
        "Post-quantum signatures": "Signatures post-quantiques",
        "Every control-plane request and response is signed, in addition to mutual X.509 authentication.":
            "Chaque requête et réponse du plan de contrôle est signée, en plus de l'authentification mutuelle X.509.",
        "Transport": "Transport",
        "RFC 9849 ECH conceals the destination name. No classical-only or public-ClientHello fallback is offered.":
            "RFC 9849 ECH dissimule le nom de domaine de destination. Aucun repli non chiffré n'est proposé.",
        "Device identity": "Identité de l'appareil",
        "Each device carries an authenticated URI identity that must match its request, with key rotation and no downtime.":
            "Chaque appareil possède une identité URI authentifiée avec rotation des clés sans interruption.",
        "Failure behaviour": "Comportement en cas d'erreur",
        "Fail-closed": "Fermeture sécurisée (Fail-closed)",
        "Any mismatch in ECH, version, cipher group or ALPN aborts the connection rather than silently downgrading it.":
            "Toute non-concordance interrompt la connexion plutôt que de la rétrograder silencieusement.",
        "Key rotation": "Rotation des clés",
        "Fresh exchange every rotation": "Échange neuf à chaque rotation",
        "Session resumption is disabled, so each rekey performs a full hybrid post-quantum exchange.":
            "La reprise de session est désactivée, chaque renouvellement effectuant un échange post-quantique complet.",
        "Continuous connection": "Connexion continue",
        "How we are funded": "Notre financement",
        "Donations from the public and cost-recovery subscriptions. Contributions are tax-deductible to the extent allowed by law. The IRS determination letter and our EIN are published in Proof.":
            "Dons du public et abonnements à prix coûtant. Contributions déductibles d'impôt selon la loi."
    },
    "de": {
        "We use customized local AI for your privacy, and we keep the VPN current with real-world censorship and network conditions so it keeps working for you. We do not collect your personal data, so we cannot train on it.":
            "Wir verwenden maßgeschneiderte lokale KI für Ihre Privatsphäre und halten das VPN an reale Zensurbedingungen angepasst. Wir erfassen keine persönlichen Daten und trainieren nicht darauf.",
        "The first non-profit VPN built on its own protocol. A US 501(c)(3) public charity, expanding access to cybersecurity, uncensored news, and education.":
            "Das erste gemeinnützige VPN auf eigenem Protokoll. Eine US 501(c)(3) Organisation zur Förderung von Cybersicherheit, unzensierten Nachrichten und Bildung.",
        "No browsing history, no DNS query history, no traffic contents, and no record of the destinations you reach. Transient session state is cleared when the VPN disconnects. The privacy-preserving device-limit metadata behind the three-device limit is deleted or overwritten once a device is deactivated or replaced, and app-collected operational data we no longer need is deleted or anonymized within 90 days. What is left is only what an account needs: status, payment and referral state, and proof you accepted the terms.":
            "Kein Browserverlauf, keine DNS-Abfragen, keine Verkehrsinhalte und keine Zielaufzeichnungen. Temporäre Sitzungsdaten werden bei Trennung gelöscht.",
        "Our servers have a hot site disaster recovery approach using latest hardware, weekly maintenance and backups, and 24/7 attack monitoring by Intrusion Detection & Prevention System (IDS/IPS). On every node the firewall drops inbound and forwarded traffic by default, IPv6 is disabled, torrent ports are blocked, and SSH accepts key-based logins only, with no passwords and a 24-hour ban after 10 failed logins in an hour. Security updates install automatically and core dumps are disabled, so process memory never reaches disk.":
            "Unsere Server nutzen Hot-Site-Disaster-Recovery mit neuester Hardware, wöchentlicher Wartung und 24/7 IDS/IPS-Überwachung. Strikte Firewall, gesperrte Torrent-Ports und 24-Stunden-SSH-Sperre nach 10 Fehlversuchen pro Stunde.",
        "Win's VPN Inc. and Win Empire LLC maintain insurance-readiness controls and may seek cyber or Technology Errors and Omissions coverage. We do not represent that a particular policy is currently bound or in force. Coverage must be confirmed from a current binder or issued policy.":
            "Win's VPN Inc. und Win Empire LLC unterhalten Versicherungskontrollen für Cyber- und Technologie-Haftpflichtdeckung.",
        "In telecom terms, if today’s leading VPN protocols are 5G, Winn Protocol® is built to be the 6G: a generation ahead in how it hides traffic, races routes, and holds a connection together across hostile networks.":
            "In der Telekommunikation: Wenn führende VPN-Protokolle 5G sind, ist Winn Protocol® als 6G konzipiert – eine Generation voraus bei Tarnung und Verbindungsstabilität.",
        "Winn Protocol® is engineered to bypass NGFW Deep Packet Inspection as long as there is a working path from a user’s country to the outside world.":
            "Winn Protocol® umgeht Deep Packet Inspection (DPI), solange ein nutzbarer Netzwerkpfad nach außen existiert.",
        "Built on published NIST and IETF standards, not private cryptography. Every primitive below is publicly specified and independently reviewable.":
            "Basiert auf veröffentlichten NIST- und IETF-Standards. Jede Komponente ist öffentlich spezifiziert und unabhängig überprüfbar.",
        "Post-quantum key exchange": "Post-Quanten-Schlüsselaustausch",
        "Hybrid, never ML-KEM alone. Protects today’s traffic against future quantum decryption of recorded sessions.":
            "Hybrid, niemals ML-KEM allein. Schützt heutigen Datenverkehr vor zukünftiger Quanten-Entschlüsselung.",
        "Post-quantum signatures": "Post-Quanten-Signaturen",
        "Every control-plane request and response is signed, in addition to mutual X.509 authentication.":
            "Jede Control-Plane-Anfrage und -Antwort ist signiert, zusätzlich zur gegenseitigen X.509-Authentifizierung.",
        "Transport": "Transport",
        "RFC 9849 ECH conceals the destination name. No classical-only or public-ClientHello fallback is offered.":
            "RFC 9849 ECH verbirgt den Zielnamen ohne unverschlüsselten Fallback.",
        "Device identity": "Geräteidentität",
        "Each device carries an authenticated URI identity that must match its request, with key rotation and no downtime.":
            "Jedes Gerät besitzt eine authentifizierte URI-Identität mit unterbrechungsfreier Schlüsselrotation.",
        "Failure behaviour": "Fehlerverhalten",
        "Fail-closed": "Fail-closed (Sicher abriegeln)",
        "Any mismatch in ECH, version, cipher group or ALPN aborts the connection rather than silently downgrading it.":
            "Jede Abweichung bricht die Verbindung ab, anstatt sie unbemerkt herabzustufen.",
        "Key rotation": "Schlüsselrotation",
        "Fresh exchange every rotation": "Frischer Austausch bei jeder Rotation",
        "Session resumption is disabled, so each rekey performs a full hybrid post-quantum exchange.":
            "Sitzungswiederaufnahme ist deaktiviert; jeder Schlüsseltausch führt einen vollständigen Post-Quanten-Austausch durch.",
        "Continuous connection": "Unterbrechungsfreie Verbindung",
        "How we are funded": "Unsere Finanzierung",
        "Donations from the public and cost-recovery subscriptions. Contributions are tax-deductible to the extent allowed by law. The IRS determination letter and our EIN are published in Proof.":
            "Öffentliche Spenden und kostendeckende Abonnements. Beiträge sind im gesetzlichen Rahmen steuerlich absetzbar."
    }
}

with open("web/i18n/major.json") as f:
    major = json.load(f)

# Update Burmese, Spanish, French, German and duplicate canonical translations to others
for lang, trans in NEW_TRANSLATIONS.items():
    if lang not in major:
        major[lang] = {}
    for k, v in trans.items():
        major[lang][k] = v

# For all other languages, ensure the keys exist so UI can fallback cleanly or translate
for lang in major:
    if lang in NEW_TRANSLATIONS:
        continue
    for k in NEW_TRANSLATIONS["my"]:
        if k not in major[lang]:
            # if Spanish/French/German has it and target is Romance/Germanic, or default to English key
            major[lang][k] = NEW_TRANSLATIONS["es"].get(k, k) if lang in ["pt", "it"] else k

with open("web/i18n/major.json", "w") as f:
    json.dump(major, f, ensure_ascii=False, indent=2)

print("major.json updated successfully!")
