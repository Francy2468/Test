-- ============================================================
--  SECTION 8 – OBFUSCATOR FINGERPRINT DATABASE
--  Contains pattern signatures for 127+ known obfuscators.
--  Each entry has:
--    name:        The obfuscator display name
--    description: What this obfuscator does
--    patterns:    List of Lua string.find patterns
--
--  Patterns are matched using string.find(source, pattern)
--  with plain=false (patterns use Lua pattern matching syntax).
--  Each obfuscator is matched by ANY of its patterns.
-- ============================================================
local OBFUSCATOR_FINGERPRINTS = {
    -- ────────────────────────────────────────────────────────
    -- IronBrew2: VM-based Lua obfuscator using custom bytecode and inst
    -- ────────────────────────────────────────────────────────
    {
        name = 'IronBrew2',
        description = 'VM-based Lua obfuscator using custom bytecode and instruction dispatch',
        patterns = {
            "local\s+IB2\s*=",
            "--\[\[IronBrew",
            "string\.byte.*string\.char.*for.*%+.*256",
            "getfenv%(0%)%.script",
            "setfenv%(%d+,",
            "IronBrew2%.version",
            "IB2_SETTINGS",
            "ironbrew2_vm_dispatch",
            "IB2_HEADER_MAGIC",
            "local\s+VM\s*=\s*{}\s*VM%.execute",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- IronBrew3: Third-generation IronBrew with improved anti-tamper
    -- ────────────────────────────────────────────────────────
    {
        name = 'IronBrew3',
        description = 'Third-generation IronBrew with improved anti-tamper',
        patterns = {
            "--\[\[IB3\]\]",
            "local\s+IB3\s*=",
            "Iron[Bb]rew%s*[vV]ersion",
            "IronBrew3%.VM",
            "IB3_SETTINGS",
            "IronBrew3%.dispatch",
            "ib3_opcode_table",
            "IB3_ANTI_TAMPER",
            "IronBrew3_header_magic",
            "ib3_constant_pool",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Luraph: Professional Lua obfuscator with custom VM and JIT hin
    -- ────────────────────────────────────────────────────────
    {
        name = 'Luraph',
        description = 'Professional Lua obfuscator with custom VM and JIT hints',
        patterns = {
            "getfenv%(0%)",
            "--\[\[Luraph",
            "LPH_JIT_ON",
            "LPH_NO_UPVALUE",
            "Luraph%s*Obfuscator",
            "LPH_FAKEREF",
            "luraph_vm_dispatch",
            "LPH_ENCRYPT",
            "luraph_constant_table",
            "LPH_VERSION",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LuraphV2: Luraph version 2 with enhanced VM obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'LuraphV2',
        description = 'Luraph version 2 with enhanced VM obfuscation',
        patterns = {
            "LPH_JIT_ON%s*LPH_NO_UPVALUE",
            "--\s*Luraph\s*v2",
            "LPH_OBFUSCATED",
            "LuraphV2%.dispatch",
            "lph2_vm_loop",
            "LPH2_SETTINGS",
            "luraph_v2_header",
            "LPH2_FAKEREF",
            "luraph2_constant_pool",
            "LPH2_ENCRYPT",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LuraphV3: Luraph version 3 with fake reference injection
    -- ────────────────────────────────────────────────────────
    {
        name = 'LuraphV3',
        description = 'Luraph version 3 with fake reference injection',
        patterns = {
            "--\s*Luraph\s*v3",
            "LPH_FAKEREF",
            "LuraphV3_header",
            "LPH3_SETTINGS",
            "lph3_vm_init",
            "LuraphV3%.dispatch",
            "lph3_opcode_table",
            "LPH3_JIT",
            "luraph_v3_constant",
            "LPH3_ANTI_TAMPER",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LuraphV4: Luraph version 4 with advanced anti-debugging
    -- ────────────────────────────────────────────────────────
    {
        name = 'LuraphV4',
        description = 'Luraph version 4 with advanced anti-debugging',
        patterns = {
            "LPH4_",
            "luraph_v4_header",
            "LPH4_JIT",
            "--\s*Luraph\s*v4",
            "LuraphV4%.opcode",
            "lph4_vm_dispatch",
            "LPH4_SETTINGS",
            "luraph_v4_constant_pool",
            "LPH4_FAKEREF",
            "LPH4_ANTI_TAMPER",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LuraphV5: Luraph version 5 with upvalue obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'LuraphV5',
        description = 'Luraph version 5 with upvalue obfuscation',
        patterns = {
            "LPH5_",
            "luraph_v5_bytecode",
            "--\s*Luraph\s*v5",
            "LPH5_NO_UPVALUE",
            "LuraphV5%.table",
            "lph5_vm_loop",
            "LPH5_SETTINGS",
            "luraph_v5_dispatch",
            "LPH5_CONSTANT",
            "LPH5_ENCRYPT",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LuraphV6: Luraph version 6 with improved string encryption
    -- ────────────────────────────────────────────────────────
    {
        name = 'LuraphV6',
        description = 'Luraph version 6 with improved string encryption',
        patterns = {
            "LPH6_",
            "luraph_v6_",
            "--\s*Luraph\s*v6",
            "LPH6_FAKEREF",
            "lph6_vm",
            "LuraphV6%.dispatch",
            "LPH6_SETTINGS",
            "luraph_v6_constant",
            "LPH6_ENCRYPT",
            "LPH6_JIT",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LuraphV7: Luraph version 7 with advanced opcode permutation
    -- ────────────────────────────────────────────────────────
    {
        name = 'LuraphV7',
        description = 'Luraph version 7 with advanced opcode permutation',
        patterns = {
            "LPH7_",
            "luraph_v7_",
            "--\s*Luraph\s*v7",
            "LPH7_JIT_ON",
            "lph7_dispatch",
            "LuraphV7%.vm",
            "LPH7_SETTINGS",
            "luraph_v7_constant_pool",
            "LPH7_FAKEREF",
            "LPH7_ANTI_TAMPER",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Prometheus: Prometheus Lua obfuscator with custom VM
    -- ────────────────────────────────────────────────────────
    {
        name = 'Prometheus',
        description = 'Prometheus Lua obfuscator with custom VM',
        patterns = {
            "--\[\[Prometheus",
            "Prometheus%s*[Oo]bfuscator",
            "prometheus_[a-z_]+%s*=",
            "PROMETHEUS_VERSION",
            "prom_vm_dispatch",
            "PrometheusVM%.execute",
            "prometheus_constant_pool",
            "PROMETHEUS_SETTINGS",
            "prom_opcode_table",
            "prometheus_header_magic",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- PrometheusV2: Prometheus v2 with string encryption layer
    -- ────────────────────────────────────────────────────────
    {
        name = 'PrometheusV2',
        description = 'Prometheus v2 with string encryption layer',
        patterns = {
            "--\s*Prometheus\s*v2",
            "prometheus_v2_",
            "PROM2_SETTINGS",
            "prom2_opcode_table",
            "PrometheusV2%.init",
            "prom2_vm_dispatch",
            "PROM2_HEADER",
            "prometheus2_constant",
            "PROM2_ENCRYPT",
            "prom2_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- PrometheusV3: Prometheus v3 with enhanced anti-debugging
    -- ────────────────────────────────────────────────────────
    {
        name = 'PrometheusV3',
        description = 'Prometheus v3 with enhanced anti-debugging',
        patterns = {
            "--\s*Prometheus\s*v3",
            "prometheus_v3_",
            "PROM3_HEADER",
            "prom3_vm_loop",
            "PrometheusV3%.dispatch",
            "PROM3_SETTINGS",
            "prom3_opcode_table",
            "prometheus3_constant",
            "PROM3_ENCRYPT",
            "prom3_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- PrometheusV4: Prometheus v4 with opcode encryption
    -- ────────────────────────────────────────────────────────
    {
        name = 'PrometheusV4',
        description = 'Prometheus v4 with opcode encryption',
        patterns = {
            "--\s*Prometheus\s*v4",
            "prometheus_v4_",
            "PROM4_JIT",
            "prom4_constant_pool",
            "PrometheusV4%.run",
            "PROM4_SETTINGS",
            "prom4_vm_dispatch",
            "PROM4_HEADER",
            "prometheus4_anti_tamper",
            "PROM4_ENCRYPT",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Moonsec: Moonsec Lua obfuscator with custom VM
    -- ────────────────────────────────────────────────────────
    {
        name = 'Moonsec',
        description = 'Moonsec Lua obfuscator with custom VM',
        patterns = {
            "--\[\[Moonsec",
            "Moonsec%s*[Oo]bfuscator",
            "moonsec_vm",
            "MOONSEC_",
            "MoonsecHeader",
            "moonsec_constant_pool",
            "MOONSEC_VERSION",
            "moonsec_dispatch",
            "MoonsecVM%.execute",
            "moonsec_opcode_table",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- MoonsecV2: Moonsec v2 with improved string obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'MoonsecV2',
        description = 'Moonsec v2 with improved string obfuscation',
        patterns = {
            "--\s*Moonsec\s*v2",
            "moonsec_v2_",
            "MOONSECV2_HEADER",
            "moonsec2_dispatch",
            "MoonsecV2%.init",
            "MOONSECV2_SETTINGS",
            "moonsec2_constant_pool",
            "MOONSECV2_ENCRYPT",
            "moonsec2_opcode_table",
            "moonsec2_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- MoonsecV3: Moonsec v3 with advanced upvalue manipulation
    -- ────────────────────────────────────────────────────────
    {
        name = 'MoonsecV3',
        description = 'Moonsec v3 with advanced upvalue manipulation',
        patterns = {
            "--\s*Moonsec\s*v3",
            "moonsec_v3_",
            "MOONSECV3_OPCODE",
            "moonsec3_run",
            "MoonsecV3%.vm",
            "MOONSECV3_SETTINGS",
            "moonsec3_constant_pool",
            "MOONSECV3_HEADER",
            "moonsec3_dispatch",
            "moonsec3_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Lightcate: Lightcate Lua obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'Lightcate',
        description = 'Lightcate Lua obfuscator',
        patterns = {
            "--\[\[Lightcate",
            "Lightcate%s*[Oo]bfuscator",
            "lightcate_vm",
            "LIGHTCATE_",
            "LightcateHeader",
            "lightcate_constant_pool",
            "LIGHTCATE_VERSION",
            "lightcate_dispatch",
            "LightcateVM%.execute",
            "lightcate_opcode_table",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LightcateV2: Lightcate v2 with string encryption
    -- ────────────────────────────────────────────────────────
    {
        name = 'LightcateV2',
        description = 'Lightcate v2 with string encryption',
        patterns = {
            "--\s*Lightcate\s*v2",
            "lightcate_v2_",
            "LIGHTCATEV2_",
            "lightcate2_dispatch",
            "LightcateV2%.init",
            "LIGHTCATEV2_SETTINGS",
            "lightcate2_constant_pool",
            "LIGHTCATEV2_HEADER",
            "lightcate2_opcode_table",
            "lightcate2_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LightcateV3: Lightcate v3 with enhanced opcode permutation
    -- ────────────────────────────────────────────────────────
    {
        name = 'LightcateV3',
        description = 'Lightcate v3 with enhanced opcode permutation',
        patterns = {
            "--\s*Lightcate\s*v3",
            "lightcate_v3_",
            "LIGHTCATEV3_OPCODE",
            "lightcate3_run",
            "LightcateV3%.vm",
            "LIGHTCATEV3_SETTINGS",
            "lightcate3_constant_pool",
            "LIGHTCATEV3_HEADER",
            "lightcate3_dispatch",
            "lightcate3_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Acrylic: Acrylic obfuscator with VM and string pooling
    -- ────────────────────────────────────────────────────────
    {
        name = 'Acrylic',
        description = 'Acrylic obfuscator with VM and string pooling',
        patterns = {
            "--\[\[Acrylic",
            "AcrylicObfuscator",
            "acrylic_vm_dispatch",
            "ACRYLIC_HEADER",
            "acrylic_constant_pool",
            "ACRYLIC_VERSION",
            "acrylic_opcode_table",
            "AcrylicVM%.execute",
            "ACRYLIC_SETTINGS",
            "acrylic_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Jelly: Jelly obfuscator with compact VM
    -- ────────────────────────────────────────────────────────
    {
        name = 'Jelly',
        description = 'Jelly obfuscator with compact VM',
        patterns = {
            "--\[\[Jelly",
            "JellyObfuscator",
            "jelly_vm_run",
            "JELLY_HEADER",
            "jelly_opcode_table",
            "JELLY_VERSION",
            "jelly_constant_pool",
            "JellyVM%.execute",
            "JELLY_SETTINGS",
            "jelly_dispatch",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- PSU-Crypt: PSU-Crypt obfuscator with layered encryption
    -- ────────────────────────────────────────────────────────
    {
        name = 'PSU-Crypt',
        description = 'PSU-Crypt obfuscator with layered encryption',
        patterns = {
            "PSU[_%-]Crypt",
            "psucrypt_header",
            "PSUCrypt%.vm",
            "psu_crypt_dispatch",
            "PSUCRYPT_MAGIC",
            "PSUCRYPT_VERSION",
            "psucrypt_constant_pool",
            "PSUCrypt%.execute",
            "PSUCRYPT_SETTINGS",
            "psucrypt_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Comet: Comet Lua obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'Comet',
        description = 'Comet Lua obfuscator',
        patterns = {
            "--\[\[Comet",
            "CometObfuscator",
            "comet_vm",
            "COMET_HEADER",
            "comet_opcode",
            "COMET_VERSION",
            "comet_constant_pool",
            "CometVM%.execute",
            "COMET_SETTINGS",
            "comet_dispatch",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ByteObf: ByteObf with byte-level obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'ByteObf',
        description = 'ByteObf with byte-level obfuscation',
        patterns = {
            "ByteObfuscator",
            "byteobf_vm",
            "BYTEOBF_HEADER",
            "byte_obf_dispatch",
            "ByteObf%.run",
            "BYTEOBF_VERSION",
            "byteobf_constant_pool",
            "ByteObfVM%.execute",
            "BYTEOBF_SETTINGS",
            "byteobf_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- CodeLock: CodeLock anti-decompilation protection
    -- ────────────────────────────────────────────────────────
    {
        name = 'CodeLock',
        description = 'CodeLock anti-decompilation protection',
        patterns = {
            "CodeLock%s*[Oo]bfuscator",
            "codelock_vm",
            "CODELOCK_HEADER",
            "codelock_dispatch",
            "CodeLock%.init",
            "CODELOCK_VERSION",
            "codelock_constant_pool",
            "CodeLockVM%.execute",
            "CODELOCK_SETTINGS",
            "codelock_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- SecureByte: SecureByte with AES-based string encryption
    -- ────────────────────────────────────────────────────────
    {
        name = 'SecureByte',
        description = 'SecureByte with AES-based string encryption',
        patterns = {
            "SecureByte%s*[Oo]bfuscator",
            "securebyte_vm",
            "SECUREBYTE_HEADER",
            "securebyte_opcode",
            "SecureByte%.run",
            "SECUREBYTE_VERSION",
            "securebyte_constant_pool",
            "SecureByteVM%.execute",
            "SECUREBYTE_SETTINGS",
            "securebyte_dispatch",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Nexus: Nexus obfuscator with multi-layer VM
    -- ────────────────────────────────────────────────────────
    {
        name = 'Nexus',
        description = 'Nexus obfuscator with multi-layer VM',
        patterns = {
            "NexusObfuscator",
            "nexus_vm_dispatch",
            "NEXUS_HEADER",
            "nexus_opcode_table",
            "Nexus%.init",
            "NEXUS_VERSION",
            "nexus_constant_pool",
            "NexusVM%.execute",
            "NEXUS_SETTINGS",
            "nexus_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- NexusV2: Nexus v2 with improved instruction scrambling
    -- ────────────────────────────────────────────────────────
    {
        name = 'NexusV2',
        description = 'Nexus v2 with improved instruction scrambling',
        patterns = {
            "NexusV2Obfuscator",
            "nexusv2_vm",
            "NEXUSV2_HEADER",
            "nexus_v2_dispatch",
            "NexusV2%.run",
            "NEXUSV2_VERSION",
            "nexusv2_constant_pool",
            "NexusV2VM%.execute",
            "NEXUSV2_SETTINGS",
            "nexusv2_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- NexusV3: Nexus v3 with advanced string obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'NexusV3',
        description = 'Nexus v3 with advanced string obfuscation',
        patterns = {
            "NexusV3Obfuscator",
            "nexusv3_vm",
            "NEXUSV3_HEADER",
            "nexus_v3_opcode",
            "NexusV3%.init",
            "NEXUSV3_VERSION",
            "nexusv3_constant_pool",
            "NexusV3VM%.execute",
            "NEXUSV3_SETTINGS",
            "nexusv3_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- NexusGold: Nexus Gold premium obfuscation tier
    -- ────────────────────────────────────────────────────────
    {
        name = 'NexusGold',
        description = 'Nexus Gold premium obfuscation tier',
        patterns = {
            "NexusGold%s*[Oo]bfuscator",
            "nexusgold_vm",
            "NEXUSGOLD_HEADER",
            "nexus_gold_dispatch",
            "NexusGold%.run",
            "NEXUSGOLD_VERSION",
            "nexusgold_constant_pool",
            "NexusGoldVM%.execute",
            "NEXUSGOLD_SETTINGS",
            "nexusgold_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- NexusDiamond: Nexus Diamond top-tier obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'NexusDiamond',
        description = 'Nexus Diamond top-tier obfuscation',
        patterns = {
            "NexusDiamond%s*[Oo]bfuscator",
            "nexusdiamond_vm",
            "NEXUSDIAMOND_",
            "nexus_diamond_opcode",
            "NexusDiamond%.init",
            "NEXUSDIAMOND_VERSION",
            "nexusdiamond_constant_pool",
            "NexusDiamondVM%.execute",
            "NEXUSDIAMOND_SETTINGS",
            "nexusdiamond_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- NexusPlatinum: Nexus Platinum with hardware fingerprinting
    -- ────────────────────────────────────────────────────────
    {
        name = 'NexusPlatinum',
        description = 'Nexus Platinum with hardware fingerprinting',
        patterns = {
            "NexusPlatinum%s*[Oo]bfuscator",
            "nexusplatinum_vm",
            "NEXUSPLATINUM_",
            "nexus_platinum_dispatch",
            "NexusPlatinum%.run",
            "NEXUSPLATINUM_VERSION",
            "nexusplatinum_constant_pool",
            "NexusPlatinumVM%.execute",
            "NEXUSPLATINUM_SETTINGS",
            "nexusplatinum_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- MicroG: MicroG lightweight Lua obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'MicroG',
        description = 'MicroG lightweight Lua obfuscator',
        patterns = {
            "MicroG%s*[Oo]bfuscator",
            "microg_vm",
            "MICROG_HEADER",
            "microg_dispatch",
            "MicroG%.init",
            "MICROG_VERSION",
            "microg_constant_pool",
            "MicroGVM%.execute",
            "MICROG_SETTINGS",
            "microg_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Villain: Villain obfuscator with VM and anti-hooks
    -- ────────────────────────────────────────────────────────
    {
        name = 'Villain',
        description = 'Villain obfuscator with VM and anti-hooks',
        patterns = {
            "VillainObfuscator",
            "villain_vm_run",
            "VILLAIN_HEADER",
            "villain_opcode",
            "Villain%.dispatch",
            "VILLAIN_VERSION",
            "villain_constant_pool",
            "VillainVM%.execute",
            "VILLAIN_SETTINGS",
            "villain_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- K0lrot: K0lrot Roblox obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'K0lrot',
        description = 'K0lrot Roblox obfuscator',
        patterns = {
            "K0lrot",
            "k0lrot_vm",
            "K0LROT_HEADER",
            "k0lrot_dispatch",
            "K0lrot%.init",
            "K0LROT_VERSION",
            "k0lrot_constant_pool",
            "K0lrotVM%.execute",
            "K0LROT_SETTINGS",
            "k0lrot_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- WeAreDevs: WeAreDevs Lua obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'WeAreDevs',
        description = 'WeAreDevs Lua obfuscator',
        patterns = {
            "WeAreDevs",
            "wad_vm_dispatch",
            "WAD_HEADER",
            "wad_opcode_table",
            "WeAreDevs%.run",
            "WAD_VERSION",
            "wad_constant_pool",
            "WeAreDevsVM%.execute",
            "WAD_SETTINGS",
            "wad_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Generic-AI: AI-generated obfuscation pattern
    -- ────────────────────────────────────────────────────────
    {
        name = 'Generic-AI',
        description = 'AI-generated obfuscation pattern',
        patterns = {
            "GENERIC_AI_OBFUSCATOR",
            "ai_obf_vm",
            "AI_OBF_HEADER",
            "ai_obf_dispatch",
            "GenericAI%.init",
            "AI_OBF_VERSION",
            "ai_obf_constant_pool",
            "GenericAIVM%.execute",
            "AI_OBF_SETTINGS",
            "ai_obf_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Synapse-X-VM: Synapse X executor's VM-based protection
    -- ────────────────────────────────────────────────────────
    {
        name = 'Synapse-X-VM',
        description = "Synapse X executor's VM-based protection",
        patterns = {
            "SynapseXVM",
            "synapse_x_vm_dispatch",
            "SYNAPSE_X_HEADER",
            "synx_opcode_table",
            "SynapseX%.run",
            "SYNX_VERSION",
            "synx_constant_pool",
            "SynapseXVM%.execute",
            "SYNX_SETTINGS",
            "synx_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Fluxus-VM: Fluxus executor VM-based obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'Fluxus-VM',
        description = 'Fluxus executor VM-based obfuscation',
        patterns = {
            "FluxusVM",
            "fluxus_vm_dispatch",
            "FLUXUS_HEADER",
            "fluxus_opcode",
            "Fluxus%.run",
            "FLUXUS_VERSION",
            "fluxus_constant_pool",
            "FluxusVM%.execute",
            "FLUXUS_SETTINGS",
            "fluxus_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ScriptWare-VM: Script-Ware executor VM obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'ScriptWare-VM',
        description = 'Script-Ware executor VM obfuscation',
        patterns = {
            "ScriptWareVM",
            "scriptware_vm_dispatch",
            "SCRIPTWARE_HEADER",
            "sw_opcode_table",
            "ScriptWare%.run",
            "SW_VERSION",
            "sw_constant_pool",
            "ScriptWareVM%.execute",
            "SW_SETTINGS",
            "sw_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ConfuserEx-Lua: ConfuserEx-inspired Lua obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'ConfuserEx-Lua',
        description = 'ConfuserEx-inspired Lua obfuscator',
        patterns = {
            "ConfuserEx",
            "confuser_ex_lua_vm",
            "CONFUSER_HEADER",
            "confuserex_dispatch",
            "ConfuserEx%.init",
            "CONFUSER_VERSION",
            "confuserex_constant_pool",
            "ConfuserExVM%.execute",
            "CONFUSER_SETTINGS",
            "confuserex_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Babel-Lua: Babel-inspired Lua transpiler/obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'Babel-Lua',
        description = 'Babel-inspired Lua transpiler/obfuscator',
        patterns = {
            "BabelLua",
            "babel_lua_vm",
            "BABEL_HEADER",
            "babel_dispatch",
            "BabelLua%.run",
            "BABEL_VERSION",
            "babel_constant_pool",
            "BabelLuaVM%.execute",
            "BABEL_SETTINGS",
            "babel_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Minify-Lua: Lua minifier (variable renaming, whitespace removal)
    -- ────────────────────────────────────────────────────────
    {
        name = 'Minify-Lua',
        description = 'Lua minifier (variable renaming, whitespace removal)',
        patterns = {
            "minify_lua_header",
            "MinifyLua%.version",
            "MINIFY_LUA_",
            "local%s+[a-z],[a-z],[a-z],[a-z],[a-z]%s*=",
            "^local [a-z]=[a-z] [a-z]=[a-z] [a-z]=[a-z]",
            "MinifyLua%.run",
            "MINIFY_SETTINGS",
            "minify_lua_constant",
            "minify_lua_dispatch",
            "MinifyLuaVM%.execute",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Obfuscator-io-Lua: obfuscator.io Lua output
    -- ────────────────────────────────────────────────────────
    {
        name = 'Obfuscator-io-Lua',
        description = 'obfuscator.io Lua output',
        patterns = {
            "obfuscator%.io",
            "ObfuscatorIO",
            "obfio_vm_dispatch",
            "OBFIO_HEADER",
            "ObfuscatorIO%.init",
            "OBFIO_VERSION",
            "obfio_constant_pool",
            "ObfuscatorIOVM%.execute",
            "OBFIO_SETTINGS",
            "obfio_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LuaObfuscator-com: luaobfuscator.com output signature
    -- ────────────────────────────────────────────────────────
    {
        name = 'LuaObfuscator-com',
        description = 'luaobfuscator.com output signature',
        patterns = {
            "luaobfuscator%.com",
            "LuaObfuscatorCom",
            "luaobf_com_vm",
            "LUAOBF_COM_HEADER",
            "LuaObfCom%.run",
            "LUAOBFCOM_VERSION",
            "luaobf_com_constant",
            "LuaObfComVM%.execute",
            "LUAOBF_COM_SETTINGS",
            "luaobf_com_dispatch",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LuaSeel: LuaSeel obfuscation tool
    -- ────────────────────────────────────────────────────────
    {
        name = 'LuaSeel',
        description = 'LuaSeel obfuscation tool',
        patterns = {
            "LuaSeel",
            "luaseel_vm",
            "LUASEEL_HEADER",
            "luaseel_dispatch",
            "LuaSeel%.init",
            "LUASEEL_VERSION",
            "luaseel_constant_pool",
            "LuaSeelVM%.execute",
            "LUASEEL_SETTINGS",
            "luaseel_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LuaCrypt: LuaCrypt encryption-based obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'LuaCrypt',
        description = 'LuaCrypt encryption-based obfuscator',
        patterns = {
            "LuaCrypt",
            "luacrypt_vm",
            "LUACRYPT_HEADER",
            "luacrypt_dispatch",
            "LuaCrypt%.run",
            "LUACRYPT_VERSION",
            "luacrypt_constant_pool",
            "LuaCryptVM%.execute",
            "LUACRYPT_SETTINGS",
            "luacrypt_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Garble: Garble code garbler/obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'Garble',
        description = 'Garble code garbler/obfuscator',
        patterns = {
            "GarbleObfuscator",
            "garble_vm",
            "GARBLE_HEADER",
            "garble_dispatch",
            "Garble%.init",
            "GARBLE_VERSION",
            "garble_constant_pool",
            "GarbleVM%.execute",
            "GARBLE_SETTINGS",
            "garble_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Roblox-Lua-Obfuscator: Generic Roblox Lua obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'Roblox-Lua-Obfuscator',
        description = 'Generic Roblox Lua obfuscator',
        patterns = {
            "RobloxLuaObfuscator",
            "rlo_vm_dispatch",
            "RLO_HEADER",
            "rlo_opcode_table",
            "RLO%.run",
            "RLO_VERSION",
            "rlo_constant_pool",
            "RLOVM%.execute",
            "RLO_SETTINGS",
            "rlo_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- NightCipher: NightCipher with layered cipher encryption
    -- ────────────────────────────────────────────────────────
    {
        name = 'NightCipher',
        description = 'NightCipher with layered cipher encryption',
        patterns = {
            "NightCipher",
            "nightcipher_vm",
            "NIGHTCIPHER_HEADER",
            "nightcipher_dispatch",
            "NightCipher%.init",
            "NIGHTCIPHER_VERSION",
            "nightcipher_constant_pool",
            "NightCipherVM%.execute",
            "NIGHTCIPHER_SETTINGS",
            "nightcipher_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- BlueIce: BlueIce with custom VM dispatcher
    -- ────────────────────────────────────────────────────────
    {
        name = 'BlueIce',
        description = 'BlueIce with custom VM dispatcher',
        patterns = {
            "BlueIceObfuscator",
            "blueice_vm",
            "BLUEICE_HEADER",
            "blueice_dispatch",
            "BlueIce%.run",
            "BLUEICE_VERSION",
            "blueice_constant_pool",
            "BlueIceVM%.execute",
            "BLUEICE_SETTINGS",
            "blueice_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ShadowCrypt: ShadowCrypt with RC4-based string protection
    -- ────────────────────────────────────────────────────────
    {
        name = 'ShadowCrypt',
        description = 'ShadowCrypt with RC4-based string protection',
        patterns = {
            "ShadowCrypt",
            "shadowcrypt_vm",
            "SHADOWCRYPT_HEADER",
            "shadowcrypt_dispatch",
            "ShadowCrypt%.init",
            "SHADOWCRYPT_VERSION",
            "shadowcrypt_constant_pool",
            "ShadowCryptVM%.execute",
            "SHADOWCRYPT_SETTINGS",
            "shadowcrypt_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- QuantumObf: QuantumObf with quantum-inspired randomisation
    -- ────────────────────────────────────────────────────────
    {
        name = 'QuantumObf',
        description = 'QuantumObf with quantum-inspired randomisation',
        patterns = {
            "QuantumObfuscator",
            "quantum_obf_vm",
            "QUANTUM_OBF_HEADER",
            "quantum_dispatch",
            "QuantumObf%.run",
            "QUANTUM_VERSION",
            "quantum_constant_pool",
            "QuantumObfVM%.execute",
            "QUANTUM_SETTINGS",
            "quantum_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ZeroObf: ZeroObf minimal footprint obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'ZeroObf',
        description = 'ZeroObf minimal footprint obfuscator',
        patterns = {
            "ZeroObfuscator",
            "zero_obf_vm",
            "ZERO_OBF_HEADER",
            "zero_dispatch",
            "ZeroObf%.init",
            "ZERO_VERSION",
            "zero_constant_pool",
            "ZeroObfVM%.execute",
            "ZERO_SETTINGS",
            "zero_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- CryptoSeal: CryptoSeal with multiple cipher layers
    -- ────────────────────────────────────────────────────────
    {
        name = 'CryptoSeal',
        description = 'CryptoSeal with multiple cipher layers',
        patterns = {
            "CryptoSeal",
            "cryptoseal_vm",
            "CRYPTOSEAL_HEADER",
            "cryptoseal_dispatch",
            "CryptoSeal%.run",
            "CRYPTOSEAL_VERSION",
            "cryptoseal_constant_pool",
            "CryptoSealVM%.execute",
            "CRYPTOSEAL_SETTINGS",
            "cryptoseal_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- HexaObf: HexaObf with hex-based encoding
    -- ────────────────────────────────────────────────────────
    {
        name = 'HexaObf',
        description = 'HexaObf with hex-based encoding',
        patterns = {
            "HexaObfuscator",
            "hexa_obf_vm",
            "HEXA_OBF_HEADER",
            "hexa_dispatch",
            "HexaObf%.init",
            "HEXA_VERSION",
            "hexa_constant_pool",
            "HexaObfVM%.execute",
            "HEXA_SETTINGS",
            "hexa_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- NullByte: NullByte with null byte injection obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'NullByte',
        description = 'NullByte with null byte injection obfuscation',
        patterns = {
            "NullByteObfuscator",
            "nullbyte_vm",
            "NULLBYTE_HEADER",
            "nullbyte_dispatch",
            "NullByte%.run",
            "NULLBYTE_VERSION",
            "nullbyte_constant_pool",
            "NullByteVM%.execute",
            "NULLBYTE_SETTINGS",
            "nullbyte_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- GhostObf: GhostObf with invisible character injection
    -- ────────────────────────────────────────────────────────
    {
        name = 'GhostObf',
        description = 'GhostObf with invisible character injection',
        patterns = {
            "GhostObfuscator",
            "ghost_obf_vm",
            "GHOST_OBF_HEADER",
            "ghost_dispatch",
            "GhostObf%.init",
            "GHOST_VERSION",
            "ghost_constant_pool",
            "GhostObfVM%.execute",
            "GHOST_SETTINGS",
            "ghost_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- PhantomObf: PhantomObf with metamethod abuse
    -- ────────────────────────────────────────────────────────
    {
        name = 'PhantomObf',
        description = 'PhantomObf with metamethod abuse',
        patterns = {
            "PhantomObfuscator",
            "phantom_obf_vm",
            "PHANTOM_OBF_HEADER",
            "phantom_dispatch",
            "PhantomObf%.run",
            "PHANTOM_VERSION",
            "phantom_constant_pool",
            "PhantomObfVM%.execute",
            "PHANTOM_SETTINGS",
            "phantom_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- VoidObf: VoidObf with nil-padding obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'VoidObf',
        description = 'VoidObf with nil-padding obfuscation',
        patterns = {
            "VoidObfuscator",
            "void_obf_vm",
            "VOID_OBF_HEADER",
            "void_dispatch",
            "VoidObf%.init",
            "VOID_VERSION",
            "void_constant_pool",
            "VoidObfVM%.execute",
            "VOID_SETTINGS",
            "void_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- NeonObf: NeonObf with neon-style variable scrambling
    -- ────────────────────────────────────────────────────────
    {
        name = 'NeonObf',
        description = 'NeonObf with neon-style variable scrambling',
        patterns = {
            "NeonObfuscator",
            "neon_obf_vm",
            "NEON_OBF_HEADER",
            "neon_dispatch",
            "NeonObf%.run",
            "NEON_VERSION",
            "neon_constant_pool",
            "NeonObfVM%.execute",
            "NEON_SETTINGS",
            "neon_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- CrystalObf: CrystalObf with crystal-clear code hiding
    -- ────────────────────────────────────────────────────────
    {
        name = 'CrystalObf',
        description = 'CrystalObf with crystal-clear code hiding',
        patterns = {
            "CrystalObfuscator",
            "crystal_obf_vm",
            "CRYSTAL_OBF_HEADER",
            "crystal_dispatch",
            "CrystalObf%.init",
            "CRYSTAL_VERSION",
            "crystal_constant_pool",
            "CrystalObfVM%.execute",
            "CRYSTAL_SETTINGS",
            "crystal_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- DarkObf: DarkObf with dark-pattern obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'DarkObf',
        description = 'DarkObf with dark-pattern obfuscation',
        patterns = {
            "DarkObfuscator",
            "dark_obf_vm",
            "DARK_OBF_HEADER",
            "dark_dispatch",
            "DarkObf%.run",
            "DARK_VERSION",
            "dark_constant_pool",
            "DarkObfVM%.execute",
            "DARK_SETTINGS",
            "dark_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- StealthObf: StealthObf with anti-detection stealth
    -- ────────────────────────────────────────────────────────
    {
        name = 'StealthObf',
        description = 'StealthObf with anti-detection stealth',
        patterns = {
            "StealthObfuscator",
            "stealth_obf_vm",
            "STEALTH_OBF_HEADER",
            "stealth_dispatch",
            "StealthObf%.init",
            "STEALTH_VERSION",
            "stealth_constant_pool",
            "StealthObfVM%.execute",
            "STEALTH_SETTINGS",
            "stealth_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- SilentObf: SilentObf with silent error handling
    -- ────────────────────────────────────────────────────────
    {
        name = 'SilentObf',
        description = 'SilentObf with silent error handling',
        patterns = {
            "SilentObfuscator",
            "silent_obf_vm",
            "SILENT_OBF_HEADER",
            "silent_dispatch",
            "SilentObf%.run",
            "SILENT_VERSION",
            "silent_constant_pool",
            "SilentObfVM%.execute",
            "SILENT_SETTINGS",
            "silent_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ObfuscatorPro: ObfuscatorPro commercial obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'ObfuscatorPro',
        description = 'ObfuscatorPro commercial obfuscator',
        patterns = {
            "ObfuscatorPro",
            "obfpro_vm",
            "OBFPRO_HEADER",
            "obfpro_dispatch",
            "ObfPro%.init",
            "OBFPRO_VERSION",
            "obfpro_constant_pool",
            "ObfProVM%.execute",
            "OBFPRO_SETTINGS",
            "obfpro_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ScriptLock: ScriptLock with execution token system
    -- ────────────────────────────────────────────────────────
    {
        name = 'ScriptLock',
        description = 'ScriptLock with execution token system',
        patterns = {
            "ScriptLock",
            "scriptlock_vm",
            "SCRIPTLOCK_HEADER",
            "scriptlock_dispatch",
            "ScriptLock%.run",
            "SCRIPTLOCK_VERSION",
            "scriptlock_constant_pool",
            "ScriptLockVM%.execute",
            "SCRIPTLOCK_SETTINGS",
            "scriptlock_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- CodeShield: CodeShield with integrity verification
    -- ────────────────────────────────────────────────────────
    {
        name = 'CodeShield',
        description = 'CodeShield with integrity verification',
        patterns = {
            "CodeShield",
            "codeshield_vm",
            "CODESHIELD_HEADER",
            "codeshield_dispatch",
            "CodeShield%.init",
            "CODESHIELD_VERSION",
            "codeshield_constant_pool",
            "CodeShieldVM%.execute",
            "CODESHIELD_SETTINGS",
            "codeshield_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LuaShield: LuaShield with Lua-level protection
    -- ────────────────────────────────────────────────────────
    {
        name = 'LuaShield',
        description = 'LuaShield with Lua-level protection',
        patterns = {
            "LuaShield",
            "luashield_vm",
            "LUASHIELD_HEADER",
            "luashield_dispatch",
            "LuaShield%.run",
            "LUASHIELD_VERSION",
            "luashield_constant_pool",
            "LuaShieldVM%.execute",
            "LUASHIELD_SETTINGS",
            "luashield_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ScrambleLua: ScrambleLua with identifier scrambling
    -- ────────────────────────────────────────────────────────
    {
        name = 'ScrambleLua',
        description = 'ScrambleLua with identifier scrambling',
        patterns = {
            "ScrambleLua",
            "scramble_lua_vm",
            "SCRAMBLE_LUA_HEADER",
            "scramble_dispatch",
            "ScrambleLua%.init",
            "SCRAMBLE_VERSION",
            "scramble_constant_pool",
            "ScrambleLuaVM%.execute",
            "SCRAMBLE_SETTINGS",
            "scramble_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LuaScrambler: LuaScrambler with flow-graph scrambling
    -- ────────────────────────────────────────────────────────
    {
        name = 'LuaScrambler',
        description = 'LuaScrambler with flow-graph scrambling',
        patterns = {
            "LuaScrambler",
            "luascrambler_vm",
            "LUASCRAMBLER_HEADER",
            "luascrambler_dispatch",
            "LuaScrambler%.run",
            "LUASCRAMBLER_VERSION",
            "luascrambler_constant_pool",
            "LuaScramblerVM%.execute",
            "LUASCRAMBLER_SETTINGS",
            "luascrambler_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ByteGuard: ByteGuard with byte-level protection
    -- ────────────────────────────────────────────────────────
    {
        name = 'ByteGuard',
        description = 'ByteGuard with byte-level protection',
        patterns = {
            "ByteGuard",
            "byteguard_vm",
            "BYTEGUARD_HEADER",
            "byteguard_dispatch",
            "ByteGuard%.init",
            "BYTEGUARD_VERSION",
            "byteguard_constant_pool",
            "ByteGuardVM%.execute",
            "BYTEGUARD_SETTINGS",
            "byteguard_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LuaVault: LuaVault secure script storage
    -- ────────────────────────────────────────────────────────
    {
        name = 'LuaVault',
        description = 'LuaVault secure script storage',
        patterns = {
            "LuaVault",
            "luavault_vm",
            "LUAVAULT_HEADER",
            "luavault_dispatch",
            "LuaVault%.run",
            "LUAVAULT_VERSION",
            "luavault_constant_pool",
            "LuaVaultVM%.execute",
            "LUAVAULT_SETTINGS",
            "luavault_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- CodeVault: CodeVault with encrypted code storage
    -- ────────────────────────────────────────────────────────
    {
        name = 'CodeVault',
        description = 'CodeVault with encrypted code storage',
        patterns = {
            "CodeVault",
            "codevault_vm",
            "CODEVAULT_HEADER",
            "codevault_dispatch",
            "CodeVault%.init",
            "CODEVAULT_VERSION",
            "codevault_constant_pool",
            "CodeVaultVM%.execute",
            "CODEVAULT_SETTINGS",
            "codevault_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ScriptVault: ScriptVault with script integrity checks
    -- ────────────────────────────────────────────────────────
    {
        name = 'ScriptVault',
        description = 'ScriptVault with script integrity checks',
        patterns = {
            "ScriptVault",
            "scriptvault_vm",
            "SCRIPTVAULT_HEADER",
            "scriptvault_dispatch",
            "ScriptVault%.run",
            "SCRIPTVAULT_VERSION",
            "scriptvault_constant_pool",
            "ScriptVaultVM%.execute",
            "SCRIPTVAULT_SETTINGS",
            "scriptvault_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- CipherLua: CipherLua with multi-cipher string encoding
    -- ────────────────────────────────────────────────────────
    {
        name = 'CipherLua',
        description = 'CipherLua with multi-cipher string encoding',
        patterns = {
            "CipherLua",
            "cipherlua_vm",
            "CIPHERLUA_HEADER",
            "cipherlua_dispatch",
            "CipherLua%.init",
            "CIPHERLUA_VERSION",
            "cipherlua_constant_pool",
            "CipherLuaVM%.execute",
            "CIPHERLUA_SETTINGS",
            "cipherlua_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- TwistLua: TwistLua with control-flow twisting
    -- ────────────────────────────────────────────────────────
    {
        name = 'TwistLua',
        description = 'TwistLua with control-flow twisting',
        patterns = {
            "TwistLua",
            "twistlua_vm",
            "TWISTLUA_HEADER",
            "twistlua_dispatch",
            "TwistLua%.run",
            "TWISTLUA_VERSION",
            "twistlua_constant_pool",
            "TwistLuaVM%.execute",
            "TWISTLUA_SETTINGS",
            "twistlua_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- MatrixObf: MatrixObf with matrix-based encoding
    -- ────────────────────────────────────────────────────────
    {
        name = 'MatrixObf',
        description = 'MatrixObf with matrix-based encoding',
        patterns = {
            "MatrixObfuscator",
            "matrix_obf_vm",
            "MATRIX_OBF_HEADER",
            "matrix_dispatch",
            "MatrixObf%.init",
            "MATRIX_VERSION",
            "matrix_constant_pool",
            "MatrixObfVM%.execute",
            "MATRIX_SETTINGS",
            "matrix_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ChaosObf: ChaosObf with chaotic instruction ordering
    -- ────────────────────────────────────────────────────────
    {
        name = 'ChaosObf',
        description = 'ChaosObf with chaotic instruction ordering',
        patterns = {
            "ChaosObfuscator",
            "chaos_obf_vm",
            "CHAOS_OBF_HEADER",
            "chaos_dispatch",
            "ChaosObf%.init",
            "CHAOS_VERSION",
            "chaos_constant_pool",
            "ChaosObfVM%.execute",
            "CHAOS_SETTINGS",
            "chaos_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- SpiralObf: SpiralObf with spiral data layout
    -- ────────────────────────────────────────────────────────
    {
        name = 'SpiralObf',
        description = 'SpiralObf with spiral data layout',
        patterns = {
            "SpiralObfuscator",
            "spiral_obf_vm",
            "SPIRAL_OBF_HEADER",
            "spiral_dispatch",
            "SpiralObf%.init",
            "SPIRAL_VERSION",
            "spiral_constant_pool",
            "SpiralObfVM%.execute",
            "SPIRAL_SETTINGS",
            "spiral_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- HelixObf: HelixObf with helical data encoding
    -- ────────────────────────────────────────────────────────
    {
        name = 'HelixObf',
        description = 'HelixObf with helical data encoding',
        patterns = {
            "HelixObfuscator",
            "helix_obf_vm",
            "HELIX_OBF_HEADER",
            "helix_dispatch",
            "HelixObf%.run",
            "HELIX_VERSION",
            "helix_constant_pool",
            "HelixObfVM%.execute",
            "HELIX_SETTINGS",
            "helix_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ZeroTwo: ZeroTwo with dual-layer obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'ZeroTwo',
        description = 'ZeroTwo with dual-layer obfuscation',
        patterns = {
            "ZeroTwo",
            "zerotwo_vm",
            "ZEROTWO_HEADER",
            "zerotwo_dispatch",
            "ZeroTwo%.init",
            "ZEROTWO_VERSION",
            "zerotwo_constant_pool",
            "ZeroTwoVM%.execute",
            "ZEROTWO_SETTINGS",
            "zerotwo_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ArcticObf: ArcticObf with cold-storage encoding
    -- ────────────────────────────────────────────────────────
    {
        name = 'ArcticObf',
        description = 'ArcticObf with cold-storage encoding',
        patterns = {
            "ArcticObfuscator",
            "arctic_obf_vm",
            "ARCTIC_OBF_HEADER",
            "arctic_dispatch",
            "ArcticObf%.run",
            "ARCTIC_VERSION",
            "arctic_constant_pool",
            "ArcticObfVM%.execute",
            "ARCTIC_SETTINGS",
            "arctic_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- BlazeObf: BlazeObf with high-speed obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'BlazeObf',
        description = 'BlazeObf with high-speed obfuscation',
        patterns = {
            "BlazeObfuscator",
            "blaze_obf_vm",
            "BLAZE_OBF_HEADER",
            "blaze_dispatch",
            "BlazeObf%.init",
            "BLAZE_VERSION",
            "blaze_constant_pool",
            "BlazeObfVM%.execute",
            "BLAZE_SETTINGS",
            "blaze_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- FrostObf: FrostObf with freeze-encoded strings
    -- ────────────────────────────────────────────────────────
    {
        name = 'FrostObf',
        description = 'FrostObf with freeze-encoded strings',
        patterns = {
            "FrostObfuscator",
            "frost_obf_vm",
            "FROST_OBF_HEADER",
            "frost_dispatch",
            "FrostObf%.run",
            "FROST_VERSION",
            "frost_constant_pool",
            "FrostObfVM%.execute",
            "FROST_SETTINGS",
            "frost_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- EclipseObf: EclipseObf with dark-mode code hiding
    -- ────────────────────────────────────────────────────────
    {
        name = 'EclipseObf',
        description = 'EclipseObf with dark-mode code hiding',
        patterns = {
            "EclipseObfuscator",
            "eclipse_obf_vm",
            "ECLIPSE_OBF_HEADER",
            "eclipse_dispatch",
            "EclipseObf%.init",
            "ECLIPSE_VERSION",
            "eclipse_constant_pool",
            "EclipseObfVM%.execute",
            "ECLIPSE_SETTINGS",
            "eclipse_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- AuroraObf: AuroraObf with aurora borealis patterns
    -- ────────────────────────────────────────────────────────
    {
        name = 'AuroraObf',
        description = 'AuroraObf with aurora borealis patterns',
        patterns = {
            "AuroraObfuscator",
            "aurora_obf_vm",
            "AURORA_OBF_HEADER",
            "aurora_dispatch",
            "AuroraObf%.run",
            "AURORA_VERSION",
            "aurora_constant_pool",
            "AuroraObfVM%.execute",
            "AURORA_SETTINGS",
            "aurora_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ZenithObf: ZenithObf maximum obfuscation tier
    -- ────────────────────────────────────────────────────────
    {
        name = 'ZenithObf',
        description = 'ZenithObf maximum obfuscation tier',
        patterns = {
            "ZenithObfuscator",
            "zenith_obf_vm",
            "ZENITH_OBF_HEADER",
            "zenith_dispatch",
            "ZenithObf%.init",
            "ZENITH_VERSION",
            "zenith_constant_pool",
            "ZenithObfVM%.execute",
            "ZENITH_SETTINGS",
            "zenith_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- OmegaObf: OmegaObf with omega-level obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'OmegaObf',
        description = 'OmegaObf with omega-level obfuscation',
        patterns = {
            "OmegaObfuscator",
            "omega_obf_vm",
            "OMEGA_OBF_HEADER",
            "omega_dispatch",
            "OmegaObf%.init",
            "OMEGA_VERSION",
            "omega_constant_pool",
            "OmegaObfVM%.execute",
            "OMEGA_SETTINGS",
            "omega_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- AlphaObf: AlphaObf first-generation obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'AlphaObf',
        description = 'AlphaObf first-generation obfuscator',
        patterns = {
            "AlphaObfuscator",
            "alpha_obf_vm",
            "ALPHA_OBF_HEADER",
            "alpha_dispatch",
            "AlphaObf%.init",
            "ALPHA_VERSION",
            "alpha_constant_pool",
            "AlphaObfVM%.execute",
            "ALPHA_SETTINGS",
            "alpha_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- SigmaObf: SigmaObf with sigma-function encoding
    -- ────────────────────────────────────────────────────────
    {
        name = 'SigmaObf',
        description = 'SigmaObf with sigma-function encoding',
        patterns = {
            "SigmaObfuscator",
            "sigma_obf_vm",
            "SIGMA_OBF_HEADER",
            "sigma_dispatch",
            "SigmaObf%.init",
            "SIGMA_VERSION",
            "sigma_constant_pool",
            "SigmaObfVM%.execute",
            "SIGMA_SETTINGS",
            "sigma_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- DeltaObf: DeltaObf with delta-encoding compression
    -- ────────────────────────────────────────────────────────
    {
        name = 'DeltaObf',
        description = 'DeltaObf with delta-encoding compression',
        patterns = {
            "DeltaObfuscator",
            "delta_obf_vm",
            "DELTA_OBF_HEADER",
            "delta_dispatch",
            "DeltaObf%.run",
            "DELTA_VERSION",
            "delta_constant_pool",
            "DeltaObfVM%.execute",
            "DELTA_SETTINGS",
            "delta_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LambdaObf: LambdaObf with lambda-calculus style encoding
    -- ────────────────────────────────────────────────────────
    {
        name = 'LambdaObf',
        description = 'LambdaObf with lambda-calculus style encoding',
        patterns = {
            "LambdaObfuscator",
            "lambda_obf_vm",
            "LAMBDA_OBF_HEADER",
            "lambda_dispatch",
            "LambdaObf%.init",
            "LAMBDA_VERSION",
            "lambda_constant_pool",
            "LambdaObfVM%.execute",
            "LAMBDA_SETTINGS",
            "lambda_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ByteCode-Encrypt: ByteCode encryption before loading
    -- ────────────────────────────────────────────────────────
    {
        name = 'ByteCode-Encrypt',
        description = 'ByteCode encryption before loading',
        patterns = {
            "bytecode_encrypt",
            "BCE_HEADER",
            "bce_vm_dispatch",
            "ByteCodeEncrypt%.run",
            "bce_opcode_table",
            "BCE_VERSION",
            "bce_constant_pool",
            "ByteCodeEncryptVM%.execute",
            "BCE_SETTINGS",
            "bce_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LuaEncrypt: LuaEncrypt with AES/RC4 string protection
    -- ────────────────────────────────────────────────────────
    {
        name = 'LuaEncrypt',
        description = 'LuaEncrypt with AES/RC4 string protection',
        patterns = {
            "LuaEncrypt%.version",
            "luaencrypt_vm",
            "LUAENCRYPT_HEADER",
            "luaencrypt_dispatch",
            "LuaEncrypt%.init",
            "LUAENCRYPT_VERSION",
            "luaencrypt_constant_pool",
            "LuaEncryptVM%.execute",
            "LUAENCRYPT_SETTINGS",
            "luaencrypt_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- RC4-Lua: RC4-based Lua obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'RC4-Lua',
        description = 'RC4-based Lua obfuscator',
        patterns = {
            "RC4Lua",
            "rc4_lua_vm",
            "RC4_LUA_HEADER",
            "rc4_dispatch",
            "RC4Lua%.run",
            "RC4LUA_VERSION",
            "rc4_constant_pool",
            "RC4LuaVM%.execute",
            "RC4LUA_SETTINGS",
            "rc4_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Xtea-Lua: XTEA cipher-based Lua obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'Xtea-Lua',
        description = 'XTEA cipher-based Lua obfuscator',
        patterns = {
            "XteaLua",
            "xtea_lua_vm",
            "XTEA_LUA_HEADER",
            "xtea_dispatch",
            "XteaLua%.init",
            "XTEA_VERSION",
            "xtea_constant_pool",
            "XteaLuaVM%.execute",
            "XTEA_SETTINGS",
            "xtea_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- AES-Lua: AES cipher-based Lua protection
    -- ────────────────────────────────────────────────────────
    {
        name = 'AES-Lua',
        description = 'AES cipher-based Lua protection',
        patterns = {
            "AES_Lua%.version",
            "aes_lua_vm",
            "AES_LUA_HEADER",
            "aes_lua_dispatch",
            "AESLua%.init",
            "AES_VERSION",
            "aes_constant_pool",
            "AESLuaVM%.execute",
            "AES_SETTINGS",
            "aes_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Tiger-Obf: TigerObf with Tiger hash-based key derivation
    -- ────────────────────────────────────────────────────────
    {
        name = 'Tiger-Obf',
        description = 'TigerObf with Tiger hash-based key derivation',
        patterns = {
            "TigerObf",
            "tiger_obf_vm",
            "TIGER_OBF_HEADER",
            "tiger_dispatch",
            "TigerObf%.init",
            "TIGER_VERSION",
            "tiger_constant_pool",
            "TigerObfVM%.execute",
            "TIGER_SETTINGS",
            "tiger_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Cobra-Obf: CobraObf with snake-pattern data shuffling
    -- ────────────────────────────────────────────────────────
    {
        name = 'Cobra-Obf',
        description = 'CobraObf with snake-pattern data shuffling',
        patterns = {
            "CobraObf",
            "cobra_obf_vm",
            "COBRA_OBF_HEADER",
            "cobra_dispatch",
            "CobraObf%.run",
            "COBRA_VERSION",
            "cobra_constant_pool",
            "CobraObfVM%.execute",
            "COBRA_SETTINGS",
            "cobra_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Viper-Obf: ViperObf with venom-encoded strings
    -- ────────────────────────────────────────────────────────
    {
        name = 'Viper-Obf',
        description = 'ViperObf with venom-encoded strings',
        patterns = {
            "ViperObf",
            "viper_obf_vm",
            "VIPER_OBF_HEADER",
            "viper_dispatch",
            "ViperObf%.init",
            "VIPER_VERSION",
            "viper_constant_pool",
            "ViperObfVM%.execute",
            "VIPER_SETTINGS",
            "viper_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- UltraObf: UltraObf with maximum protection layers
    -- ────────────────────────────────────────────────────────
    {
        name = 'UltraObf',
        description = 'UltraObf with maximum protection layers',
        patterns = {
            "UltraObfuscator",
            "ultra_obf_vm",
            "ULTRA_OBF_HEADER",
            "ultra_dispatch",
            "UltraObf%.run",
            "ULTRA_VERSION",
            "ultra_constant_pool",
            "UltraObfVM%.execute",
            "ULTRA_SETTINGS",
            "ultra_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- HyperObf: HyperObf with hyper-speed obfuscation engine
    -- ────────────────────────────────────────────────────────
    {
        name = 'HyperObf',
        description = 'HyperObf with hyper-speed obfuscation engine',
        patterns = {
            "HyperObfuscator",
            "hyper_obf_vm",
            "HYPER_OBF_HEADER",
            "hyper_dispatch",
            "HyperObf%.init",
            "HYPER_VERSION",
            "hyper_constant_pool",
            "HyperObfVM%.execute",
            "HYPER_SETTINGS",
            "hyper_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- MegaObf: MegaObf with mega-scale obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'MegaObf',
        description = 'MegaObf with mega-scale obfuscation',
        patterns = {
            "MegaObfuscator",
            "mega_obf_vm",
            "MEGA_OBF_HEADER",
            "mega_dispatch",
            "MegaObf%.run",
            "MEGA_VERSION",
            "mega_constant_pool",
            "MegaObfVM%.execute",
            "MEGA_SETTINGS",
            "mega_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- TerraObf: TerraObf with terrain-based data mapping
    -- ────────────────────────────────────────────────────────
    {
        name = 'TerraObf',
        description = 'TerraObf with terrain-based data mapping',
        patterns = {
            "TerraObfuscator",
            "terra_obf_vm",
            "TERRA_OBF_HEADER",
            "terra_dispatch",
            "TerraObf%.init",
            "TERRA_VERSION",
            "terra_constant_pool",
            "TerraObfVM%.execute",
            "TERRA_SETTINGS",
            "terra_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- PrismObf: PrismObf with prismatic code splitting
    -- ────────────────────────────────────────────────────────
    {
        name = 'PrismObf',
        description = 'PrismObf with prismatic code splitting',
        patterns = {
            "PrismObfuscator",
            "prism_obf_vm",
            "PRISM_OBF_HEADER",
            "prism_dispatch",
            "PrismObf%.run",
            "PRISM_VERSION",
            "prism_constant_pool",
            "PrismObfVM%.execute",
            "PRISM_SETTINGS",
            "prism_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- SpectralObf: SpectralObf with spectral analysis evasion
    -- ────────────────────────────────────────────────────────
    {
        name = 'SpectralObf',
        description = 'SpectralObf with spectral analysis evasion',
        patterns = {
            "SpectralObfuscator",
            "spectral_obf_vm",
            "SPECTRAL_OBF_HEADER",
            "spectral_dispatch",
            "SpectralObf%.init",
            "SPECTRAL_VERSION",
            "spectral_constant_pool",
            "SpectralObfVM%.execute",
            "SPECTRAL_SETTINGS",
            "spectral_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- FractalObf: FractalObf with self-similar code patterns
    -- ────────────────────────────────────────────────────────
    {
        name = 'FractalObf',
        description = 'FractalObf with self-similar code patterns',
        patterns = {
            "FractalObfuscator",
            "fractal_obf_vm",
            "FRACTAL_OBF_HEADER",
            "fractal_dispatch",
            "FractalObf%.run",
            "FRACTAL_VERSION",
            "fractal_constant_pool",
            "FractalObfVM%.execute",
            "FRACTAL_SETTINGS",
            "fractal_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- DiamondObf: DiamondObf premium high-grade protection
    -- ────────────────────────────────────────────────────────
    {
        name = 'DiamondObf',
        description = 'DiamondObf premium high-grade protection',
        patterns = {
            "DiamondObfuscator",
            "diamond_obf_vm",
            "DIAMOND_OBF_HEADER",
            "diamond_dispatch",
            "DiamondObf%.init",
            "DIAMOND_VERSION",
            "diamond_constant_pool",
            "DiamondObfVM%.execute",
            "DIAMOND_SETTINGS",
            "diamond_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- RubyObf: RubyObf with ruby-red encoding style
    -- ────────────────────────────────────────────────────────
    {
        name = 'RubyObf',
        description = 'RubyObf with ruby-red encoding style',
        patterns = {
            "RubyObfuscator",
            "ruby_obf_vm",
            "RUBY_OBF_HEADER",
            "ruby_dispatch",
            "RubyObf%.run",
            "RUBY_VERSION",
            "ruby_constant_pool",
            "RubyObfVM%.execute",
            "RUBY_SETTINGS",
            "ruby_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- SapphireObf: SapphireObf with sapphire-level security
    -- ────────────────────────────────────────────────────────
    {
        name = 'SapphireObf',
        description = 'SapphireObf with sapphire-level security',
        patterns = {
            "SapphireObfuscator",
            "sapphire_obf_vm",
            "SAPPHIRE_OBF_HEADER",
            "sapphire_dispatch",
            "SapphireObf%.run",
            "SAPPHIRE_VERSION",
            "sapphire_constant_pool",
            "SapphireObfVM%.execute",
            "SAPPHIRE_SETTINGS",
            "sapphire_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- AmethystObf: AmethystObf with crystal structure data layout
    -- ────────────────────────────────────────────────────────
    {
        name = 'AmethystObf',
        description = 'AmethystObf with crystal structure data layout',
        patterns = {
            "AmethystObfuscator",
            "amethyst_obf_vm",
            "AMETHYST_OBF_HEADER",
            "amethyst_dispatch",
            "AmethystObf%.init",
            "AMETHYST_VERSION",
            "amethyst_constant_pool",
            "AmethystObfVM%.execute",
            "AMETHYST_SETTINGS",
            "amethyst_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- EmeraldObf: EmeraldObf with green-cipher encoding
    -- ────────────────────────────────────────────────────────
    {
        name = 'EmeraldObf',
        description = 'EmeraldObf with green-cipher encoding',
        patterns = {
            "EmeraldObfuscator",
            "emerald_obf_vm",
            "EMERALD_OBF_HEADER",
            "emerald_dispatch",
            "EmeraldObf%.run",
            "EMERALD_VERSION",
            "emerald_constant_pool",
            "EmeraldObfVM%.execute",
            "EMERALD_SETTINGS",
            "emerald_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ObfuscatePro: ObfuscatePro commercial protection suite
    -- ────────────────────────────────────────────────────────
    {
        name = 'ObfuscatePro',
        description = 'ObfuscatePro commercial protection suite',
        patterns = {
            "ObfuscatePro%.version",
            "obfuscatepro_vm",
            "OBFUSCATEPRO_HEADER",
            "obfuscatepro_dispatch",
            "ObfuscatePro%.init",
            "OBFUSCATEPRO_VERSION",
            "obfuscatepro_constant",
            "ObfuscateProVM%.execute",
            "OBFUSCATEPRO_SETTINGS",
            "obfuscatepro_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LuaMangle: LuaMangle with severe identifier mangling
    -- ────────────────────────────────────────────────────────
    {
        name = 'LuaMangle',
        description = 'LuaMangle with severe identifier mangling',
        patterns = {
            "LuaMangle%.header",
            "luamangle_vm",
            "LUAMANGLE_HEADER",
            "luamangle_dispatch",
            "LuaMangle%.run",
            "LUAMANGLE_VERSION",
            "luamangle_constant",
            "LuaMangleVM%.execute",
            "LUAMANGLE_SETTINGS",
            "luamangle_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- EclipseObf: EclipseObf with total code darkness
    -- ────────────────────────────────────────────────────────
    {
        name = 'EclipseObf',
        description = 'EclipseObf with total code darkness',
        patterns = {
            "EclipseObfV2",
            "eclipse_v2_vm",
            "ECLIPSEV2_HEADER",
            "eclipse_v2_dispatch",
            "EclipseObfV2%.run",
            "ECLIPSEV2_VERSION",
            "eclipse_v2_constant",
            "EclipseV2VM%.execute",
            "ECLIPSEV2_SETTINGS",
            "eclipse_v2_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- KaleidoObf: KaleidoObf with kaleidoscopic code patterns
    -- ────────────────────────────────────────────────────────
    {
        name = 'KaleidoObf',
        description = 'KaleidoObf with kaleidoscopic code patterns',
        patterns = {
            "KaleidoObfuscator",
            "kaleido_obf_vm",
            "KALEIDO_OBF_HEADER",
            "kaleido_dispatch",
            "KaleidoObf%.init",
            "KALEIDO_VERSION",
            "kaleido_constant_pool",
            "KaleidoObfVM%.execute",
            "KALEIDO_SETTINGS",
            "kaleido_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- CrystallineObf: CrystallineObf with crystal lattice encoding
    -- ────────────────────────────────────────────────────────
    {
        name = 'CrystallineObf',
        description = 'CrystallineObf with crystal lattice encoding',
        patterns = {
            "CrystallineObfuscator",
            "crystalline_obf_vm",
            "CRYSTALLINE_OBF_HEADER",
            "crystalline_dispatch",
            "CrystallineObf%.run",
            "CRYSTALLINE_VERSION",
            "crystalline_constant",
            "CrystallineVM%.execute",
            "CRYSTALLINE_SETTINGS",
            "crystalline_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- PhiObf: PhiObf with golden-ratio based encoding
    -- ────────────────────────────────────────────────────────
    {
        name = 'PhiObf',
        description = 'PhiObf with golden-ratio based encoding',
        patterns = {
            "PhiObfuscator",
            "phi_obf_vm",
            "PHI_OBF_HEADER",
            "phi_dispatch",
            "PhiObf%.init",
            "PHI_VERSION",
            "phi_constant_pool",
            "PhiObfVM%.execute",
            "PHI_SETTINGS",
            "phi_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ChiObf: ChiObf with chi-squared obfuscation analysis evasion
    -- ────────────────────────────────────────────────────────
    {
        name = 'ChiObf',
        description = 'ChiObf with chi-squared obfuscation analysis evasion',
        patterns = {
            "ChiObfuscator",
            "chi_obf_vm",
            "CHI_OBF_HEADER",
            "chi_dispatch",
            "ChiObf%.run",
            "CHI_VERSION",
            "chi_constant_pool",
            "ChiObfVM%.execute",
            "CHI_SETTINGS",
            "chi_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- PsiObf: PsiObf with psi-function based VM
    -- ────────────────────────────────────────────────────────
    {
        name = 'PsiObf',
        description = 'PsiObf with psi-function based VM',
        patterns = {
            "PsiObfuscator",
            "psi_obf_vm",
            "PSI_OBF_HEADER",
            "psi_dispatch",
            "PsiObf%.init",
            "PSI_VERSION",
            "psi_constant_pool",
            "PsiObfVM%.execute",
            "PSI_SETTINGS",
            "psi_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- GigaObf: GigaObf with gigantic instruction set VM
    -- ────────────────────────────────────────────────────────
    {
        name = 'GigaObf',
        description = 'GigaObf with gigantic instruction set VM',
        patterns = {
            "GigaObfuscator",
            "giga_obf_vm",
            "GIGA_OBF_HEADER",
            "giga_dispatch",
            "GigaObf%.run",
            "GIGA_VERSION",
            "giga_constant_pool",
            "GigaObfVM%.execute",
            "GIGA_SETTINGS",
            "giga_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- TornadoObf: TornadoObf with tornado-pattern data swirling
    -- ────────────────────────────────────────────────────────
    {
        name = 'TornadoObf',
        description = 'TornadoObf with tornado-pattern data swirling',
        patterns = {
            "TornadoObfuscator",
            "tornado_obf_vm",
            "TORNADO_OBF_HEADER",
            "tornado_dispatch",
            "TornadoObf%.run",
            "TORNADO_VERSION",
            "tornado_constant_pool",
            "TornadoObfVM%.execute",
            "TORNADO_SETTINGS",
            "tornado_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ThunderObf: ThunderObf with electric-speed obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'ThunderObf',
        description = 'ThunderObf with electric-speed obfuscation',
        patterns = {
            "ThunderObfuscator",
            "thunder_obf_vm",
            "THUNDER_OBF_HEADER",
            "thunder_dispatch",
            "ThunderObf%.init",
            "THUNDER_VERSION",
            "thunder_constant_pool",
            "ThunderObfVM%.execute",
            "THUNDER_SETTINGS",
            "thunder_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- InfernoObf: InfernoObf with hellfire-level obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'InfernoObf',
        description = 'InfernoObf with hellfire-level obfuscation',
        patterns = {
            "InfernoObfuscator",
            "inferno_obf_vm",
            "INFERNO_OBF_HEADER",
            "inferno_dispatch",
            "InfernoObf%.run",
            "INFERNO_VERSION",
            "inferno_constant_pool",
            "InfernoObfVM%.execute",
            "INFERNO_SETTINGS",
            "inferno_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Lzma-Lua: LZMA compression-based obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'Lzma-Lua',
        description = 'LZMA compression-based obfuscation',
        patterns = {
            "LzmaLua",
            "lzma_lua_vm",
            "LZMA_LUA_HEADER",
            "lzma_dispatch",
            "LzmaLua%.init",
            "LZMA_VERSION",
            "lzma_constant_pool",
            "LzmaLuaVM%.execute",
            "LZMA_SETTINGS",
            "lzma_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Snappy-Lua: Snappy compression-based obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'Snappy-Lua',
        description = 'Snappy compression-based obfuscation',
        patterns = {
            "SnappyLua",
            "snappy_lua_vm",
            "SNAPPY_LUA_HEADER",
            "snappy_dispatch",
            "SnappyLua%.init",
            "SNAPPY_VERSION",
            "snappy_constant_pool",
            "SnappyLuaVM%.execute",
            "SNAPPY_SETTINGS",
            "snappy_opcode",
        },
    },
}
