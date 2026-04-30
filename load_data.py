import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
django.setup()

from security_checker.models import CloudProvider, SecurityProtocol, CloudComplianceData

# Удаляем старые данные (если нужно пересоздать)
CloudProvider.objects.all().delete()
SecurityProtocol.objects.all().delete()
CloudComplianceData.objects.all().delete()

# Создаём Yandex Cloud как основной провайдер
yandex, _ = CloudProvider.objects.get_or_create(
    name="Yandex Cloud",
    defaults={
        "description": "Основная облачная платформа Яндекс",
        "region": "ru-central1",
        "is_active": True
    }
)

# Создаём суб-облака (проекты/подразделения компании)
sub_clouds = [
    {
        "name": "Yandex Cloud | Проект «Бухгалтерия»",
        "description": "Облачные ресурсы для бухгалтерии и финансов",
        "region": "ru-central1-a"
    },
    {
        "name": "Yandex Cloud | Проект «Маркетинг»",
        "description": "Аналитика, CRM, рекламные кампании",
        "region": "ru-central1-b"
    },
    {
        "name": "Yandex Cloud | Проект «Разработка»",
        "description": "Dev/Test среда, CI/CD, репозитории",
        "region": "ru-central1-a"
    },
    {
        "name": "Yandex Cloud | Проект «HR и кадры»",
        "description": "Персональные данные сотрудников, кадровый учёт",
        "region": "ru-central1-c"
    },
    {
        "name": "Yandex Cloud | Проект «Аналитика BigData»",
        "description": "Data Lake, обработка больших данных",
        "region": "ru-central1-a"
    },
]

sub_cloud_objects = []
for sub_data in sub_clouds:
    sub, _ = CloudProvider.objects.get_or_create(
        name=sub_data["name"],
        defaults={
            "description": sub_data["description"],
            "region": sub_data["region"],
            "is_active": True
        }
    )
    sub_cloud_objects.append(sub)

print(f"✅ Создан Yandex Cloud и {len(sub_cloud_objects)} суб-облаков")

# Создаём протоколы безопасности
protocols_data = [
    {
        "protocol_id": "152-FZ",
        "name": "О персональных данных",
        "category": "COMPLIANCE",
        "description": "Федеральный закон №152-ФЗ",
        "standard": "152-ФЗ",
        "severity_on_fail": "CRITICAL",
        "remediation_template": "Хранить ПД на серверах в РФ, получить согласия",
        "responsibility": "shared",
        "priority": 1
    },
    {
        "protocol_id": "GOST-57580",
        "name": "ГОСТ Р 57580 (безопасность облачных сервисов)",
        "category": "COMPLIANCE",
        "description": "Сертификация облачной инфраструктуры",
        "standard": "ГОСТ Р 57580",
        "severity_on_fail": "CRITICAL",
        "remediation_template": "Пройти сертификацию",
        "responsibility": "provider",
        "priority": 1
    },
    {
        "protocol_id": "ENCRYPTION",
        "name": "Шифрование данных при хранении",
        "category": "ENCRYPTION",
        "description": "Обязательное шифрование бакетов",
        "standard": "Yandex KMS",
        "severity_on_fail": "CRITICAL",
        "remediation_template": "Включить шифрование бакета через KMS",
        "responsibility": "consumer",
        "priority": 1
    },
    {
        "protocol_id": "PUBLIC-BUCKET",
        "name": "Публичный доступ к бакетам",
        "category": "STORAGE",
        "description": "Запрет публичного доступа к бакетам с ПД",
        "standard": "Yandex Best Practices",
        "severity_on_fail": "CRITICAL",
        "remediation_template": "Отключить публичный доступ",
        "responsibility": "consumer",
        "priority": 1
    },
    {
        "protocol_id": "VERSIONING",
        "name": "Версионирование объектов",
        "category": "STORAGE",
        "description": "Защита от случайного удаления",
        "standard": "Yandex Object Storage",
        "severity_on_fail": "WARNING",
        "remediation_template": "Включить версионирование в бакете",
        "responsibility": "consumer",
        "priority": 2
    },
    {
        "protocol_id": "AUDIT-TRAILS",
        "name": "Логирование действий",
        "category": "STORAGE",
        "description": "Аудит операций с бакетами",
        "standard": "Yandex Audit Trails",
        "severity_on_fail": "WARNING",
        "remediation_template": "Настроить Audit Trails",
        "responsibility": "consumer",
        "priority": 2
    },
    {
        "protocol_id": "IAM-POLICY",
        "name": "Минимальные привилегии IAM",
        "category": "IAM",
        "description": "Отсутствие избыточных прав",
        "standard": "Yandex IAM",
        "severity_on_fail": "CRITICAL",
        "remediation_template": "Назначить минимально необходимые роли",
        "responsibility": "consumer",
        "priority": 1
    },
    {
        "protocol_id": "LIFECYCLE",
        "name": "Политики жизненного цикла",
        "category": "STORAGE",
        "description": "Автоматическое перемещение в холодное хранилище",
        "standard": "Yandex Object Storage",
        "severity_on_fail": "INFO",
        "remediation_template": "Настроить правила жизненного цикла",
        "responsibility": "consumer",
        "priority": 3
    },
]

protocols = {}
for proto_data in protocols_data:
    proto, _ = SecurityProtocol.objects.get_or_create(
        protocol_id=proto_data["protocol_id"],
        defaults=proto_data
    )
    protocols[proto_data["protocol_id"]] = proto

print(f"✅ Создано {len(protocols)} протоколов безопасности")

# Данные о соответствии для каждого суб-облака
compliance_map = {
    "Yandex Cloud | Проект «Бухгалтерия»": [
        ("152-FZ", True, 95, "✅ Все ПД хранятся в РФ"),
        ("ENCRYPTION", True, 100, "✅ Шифрование включено"),
        ("PUBLIC-BUCKET", True, 100, "✅ Доступ только по IAM"),
        ("IAM-POLICY", True, 90, "✅ Роли настроены корректно"),
    ],
    "Yandex Cloud | Проект «Маркетинг»": [
        ("152-FZ", False, 40, "❌ Часть данных хранится вне РФ"),
        ("ENCRYPTION", True, 100, "✅ Шифрование включено"),
        ("PUBLIC-BUCKET", False, 0, "❌ Бакет с отчётами публичен!"),
        ("VERSIONING", False, 0, "❌ Версионирование отключено"),
    ],
    "Yandex Cloud | Проект «Разработка»": [
        ("ENCRYPTION", False, 0, "❌ Шифрование не используется"),
        ("PUBLIC-BUCKET", False, 0, "❌ Тестовые бакеты публичны"),
        ("IAM-POLICY", False, 30, "❌ Разработчики имеют admin права"),
        ("AUDIT-TRAILS", False, 0, "❌ Логирование отключено"),
    ],
    "Yandex Cloud | Проект «HR и кадры»": [
        ("152-FZ", True, 98, "✅ Полное соответствие"),
        ("ENCRYPTION", True, 100, "✅ Шифрование включено"),
        ("PUBLIC-BUCKET", True, 100, "✅ Нет публичных бакетов"),
        ("GOST-57580", False, 50, "⚠️ Сертификация в процессе"),
    ],
    "Yandex Cloud | Проект «Аналитика BigData»": [
        ("ENCRYPTION", True, 100, "✅ Все данные зашифрованы"),
        ("LIFECYCLE", False, 0, "❌ Нет политик жизненного цикла"),
        ("VERSIONING", True, 100, "✅ Версионирование включено"),
        ("IAM-POLICY", True, 85, "✅ Роли настроены"),
    ],
}

for sub in sub_cloud_objects:
    if sub.name in compliance_map:
        for proto_id, is_compliant, level, notes in compliance_map[sub.name]:
            protocol = protocols.get(proto_id)
            if protocol:
                CloudComplianceData.objects.update_or_create(
                    cloud=sub,
                    protocol=protocol,
                    defaults={
                        "is_compliant": is_compliant,
                        "compliance_level": level,
                        "notes": notes
                    }
                )

print("✅ Данные о соответствии загружены")
print("\n📊 Доступные облака для проверки:")
for sub in sub_cloud_objects:
    issues = CloudComplianceData.objects.filter(cloud=sub, is_compliant=False).count()
    status = "🔴" if issues > 0 else "🟢"
    print(f"   {status} {sub.name} ({issues} проблем)")