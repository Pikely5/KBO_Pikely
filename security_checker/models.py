"""
Модели базы данных для системы проверки безопасности облака
Вариант 32 - Контейнер безопасности облака
Автор: Петров Виктор

Данный модуль содержит определения моделей Django ORM для хранения
информации об облачных проектах, протоколах безопасности, данных
о соответствии, истории проверок и выявленных нарушениях.
"""

from django.db import models
from django.utils import timezone


class CloudProvider(models.Model):
    """
    Модель облачного провайдера (проекта/суб-облака).

    Содержит информацию об облачных проектах Yandex Cloud,
    используемых в организации. Каждый проект представляет собой
    отдельное суб-облако или каталог в Yandex Cloud.

    Attributes:
        name (CharField): Уникальное наименование облачного проекта
        description (TextField): Текстовое описание проекта
        region (CharField): Регион размещения ресурсов (по умолчанию ru-central1)
        is_active (BooleanField): Флаг активности проекта
        created_at (DateTimeField): Дата и время создания записи
    """
    name = models.CharField(
        max_length=100,
        unique=True,
        verbose_name="Название"
    )
    description = models.TextField(
        blank=True,
        verbose_name="Описание"
    )
    region = models.CharField(
        max_length=50,
        default="ru-central1",
        verbose_name="Регион"
    )
    is_active = models.BooleanField(
        default=True,
        verbose_name="Активен"
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Дата добавления"
    )

    class Meta:
        verbose_name = "Облачный провайдер"
        verbose_name_plural = "Облачные провайдеры"
        ordering = ['name']

    def __str__(self):
        """Строковое представление объекта."""
        return self.name


class SecurityProtocol(models.Model):
    """
    Модель протокола безопасности.

    Определяет критерии проверки безопасности и действия,
    которые необходимо предпринять при выявлении нарушений.

    Attributes:
        protocol_id (CharField): Уникальный идентификатор протокола
        name (CharField): Наименование протокола
        category (CharField): Категория протокола (STORAGE, IAM, SLA, ENCRYPTION, NETWORK, COMPLIANCE)
        description (TextField): Подробное описание проверяемого аспекта
        standard (CharField): Наименование стандарта или нормативного документа
        severity_on_fail (CharField): Уровень критичности при обнаружении нарушения
        remediation_template (TextField): Шаблон рекомендации по устранению
        responsibility (CharField): Зона ответственности (provider, consumer, shared)
        is_active (BooleanField): Флаг активности протокола
        priority (IntegerField): Приоритет проверки (меньше = выше приоритет)
    """
    PROTOCOL_CATEGORIES = [
        ('STORAGE', 'Хранилища данных'),
        ('IAM', 'Управление доступом'),
        ('SLA', 'Соглашение об уровне обслуживания'),
        ('ENCRYPTION', 'Шифрование'),
        ('NETWORK', 'Сетевая безопасность'),
        ('COMPLIANCE', 'Соответствие стандартам'),
    ]

    protocol_id = models.CharField(
        max_length=50,
        unique=True,
        verbose_name="ID протокола"
    )
    name = models.CharField(
        max_length=200,
        verbose_name="Название протокола"
    )
    category = models.CharField(
        max_length=20,
        choices=PROTOCOL_CATEGORIES,
        verbose_name="Категория"
    )
    description = models.TextField(
        verbose_name="Описание"
    )
    standard = models.CharField(
        max_length=100,
        blank=True,
        verbose_name="Стандарт"
    )
    severity_on_fail = models.CharField(
        max_length=20,
        choices=[
            ('CRITICAL', 'Критический'),
            ('HIGH', 'Высокий'),
            ('MEDIUM', 'Средний'),
            ('WARNING', 'Предупреждение'),
            ('INFO', 'Информационный')
        ],
        default='WARNING',
        verbose_name="Критичность при нарушении"
    )
    remediation_template = models.TextField(
        verbose_name="Шаблон рекомендации"
    )
    responsibility = models.CharField(
        max_length=20,
        choices=[
            ('provider', 'Поставщик'),
            ('consumer', 'Потребитель'),
            ('shared', 'Совместная')
        ],
        default='consumer',
        verbose_name="Ответственность"
    )
    is_active = models.BooleanField(
        default=True,
        verbose_name="Активен"
    )
    priority = models.IntegerField(
        default=0,
        verbose_name="Приоритет"
    )

    class Meta:
        verbose_name = "Протокол безопасности"
        verbose_name_plural = "Протоколы безопасности"
        ordering = ['category', 'priority']

    def __str__(self):
        """Строковое представление объекта."""
        return f"{self.protocol_id}: {self.name}"


class CloudComplianceData(models.Model):
    """
    Модель данных о соответствии облачного проекта протоколу безопасности.

    Связывает облачный проект с протоколом и хранит информацию о том,
    соответствует ли проект данному протоколу, а также дополнительные
    сведения о проверке.

    Attributes:
        cloud (ForeignKey): Ссылка на облачный проект
        protocol (ForeignKey): Ссылка на протокол безопасности
        is_compliant (BooleanField): Флаг соответствия требованиям
        compliance_level (IntegerField): Уровень соответствия в процентах (0-100)
        last_checked (DateTimeField): Дата и время последней проверки
        notes (TextField): Примечания и детали проверки
        raw_data (JSONField): Сырые данные, полученные от API (опционально)
    """
    cloud = models.ForeignKey(
        CloudProvider,
        on_delete=models.CASCADE,
        related_name='compliance_data',
        verbose_name="Облако"
    )
    protocol = models.ForeignKey(
        SecurityProtocol,
        on_delete=models.CASCADE,
        related_name='cloud_data',
        verbose_name="Протокол"
    )
    is_compliant = models.BooleanField(
        default=False,
        verbose_name="Соответствует"
    )
    compliance_level = models.IntegerField(
        default=0,
        verbose_name="Уровень соответствия (%)"
    )
    last_checked = models.DateTimeField(
        auto_now=True,
        verbose_name="Последняя проверка"
    )
    notes = models.TextField(
        blank=True,
        verbose_name="Примечания"
    )
    raw_data = models.JSONField(
        default=dict,
        verbose_name="Сырые данные"
    )

    class Meta:
        verbose_name = "Соответствие облака протоколу"
        verbose_name_plural = "Соответствие облаков протоколам"
        unique_together = ['cloud', 'protocol']
        ordering = ['cloud', 'protocol__category', 'protocol']

    def __str__(self):
        """Строковое представление объекта."""
        status = "✅" if self.is_compliant else "❌"
        return f"{self.cloud.name} - {self.protocol.name} {status}"


class TestProtocol(models.Model):
    """
    Модель протокола тестирования.

    Сохраняет информацию о каждой проведённой проверке безопасности:
    когда, кем, для какого облачного проекта, с какими протоколами,
    а также результаты проверки в агрегированном виде.

    Attributes:
        protocol_number (CharField): Уникальный номер протокола (автогенерируемый)
        test_date (DateTimeField): Дата и время проведения проверки
        tester_name (CharField): Имя тестировщика
        cloud (ForeignKey): Ссылка на проверяемый облачный проект
        selected_protocols (ManyToManyField): Список выбранных протоколов
        status (CharField): Итоговый статус проверки (SUCCESS/WARNING/FAILED/IN_PROGRESS)
        total_checks (IntegerField): Общее количество выполненных проверок
        passed_checks (IntegerField): Количество успешно пройденных проверок
        failed_checks (IntegerField): Количество проваленных проверок
        risk_score (FloatField): Рассчитанный уровень риска (0-100)
        compliance_percent (FloatField): Рассчитанный процент соответствия
        detailed_results (JSONField): Детальные результаты в формате JSON
        recommendations (TextField): Сводный текст рекомендаций
        test_duration (FloatField): Длительность проверки в секундах
    """
    PROTOCOL_STATUS = [
        ('SUCCESS', 'Успешно'),
        ('WARNING', 'С предупреждениями'),
        ('FAILED', 'Провален'),
        ('IN_PROGRESS', 'В процессе'),
    ]

    protocol_number = models.CharField(
        max_length=50,
        unique=True,
        verbose_name="Номер протокола"
    )
    test_date = models.DateTimeField(
        default=timezone.now,
        verbose_name="Дата тестирования"
    )
    tester_name = models.CharField(
        max_length=100,
        default="Петров Виктор",
        verbose_name="Тестировщик"
    )
    cloud = models.ForeignKey(
        CloudProvider,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        verbose_name="Облако"
    )
    selected_protocols = models.ManyToManyField(
        SecurityProtocol,
        blank=True,
        verbose_name="Выбранные протоколы"
    )
    status = models.CharField(
        max_length=20,
        choices=PROTOCOL_STATUS,
        default='IN_PROGRESS',
        verbose_name="Статус"
    )
    total_checks = models.IntegerField(
        default=0,
        verbose_name="Всего проверок"
    )
    passed_checks = models.IntegerField(
        default=0,
        verbose_name="Пройдено проверок"
    )
    failed_checks = models.IntegerField(
        default=0,
        verbose_name="Провалено проверок"
    )
    risk_score = models.FloatField(
        default=0.0,
        verbose_name="Оценка риска"
    )
    compliance_percent = models.FloatField(
        default=0.0,
        verbose_name="Процент соответствия"
    )
    detailed_results = models.JSONField(
        default=dict,
        verbose_name="Детальные результаты"
    )
    recommendations = models.TextField(
        blank=True,
        verbose_name="Рекомендации"
    )
    test_duration = models.FloatField(
        default=0.0,
        verbose_name="Длительность теста (сек)"
    )

    class Meta:
        verbose_name = "Протокол тестирования"
        verbose_name_plural = "Протоколы тестирования"
        ordering = ['-test_date']

    def __str__(self):
        """Строковое представление объекта."""
        return f"Протокол №{self.protocol_number}"

    def generate_protocol_number(self):
        """
        Генерирует уникальный номер протокола в формате SEC-YYYYMMDD-XXXX.

        Returns:
            str: Сгенерированный номер протокола
        """
        from datetime import datetime
        date_str = datetime.now().strftime("%Y%m%d")
        count = TestProtocol.objects.filter(
            protocol_number__startswith=f"SEC-{date_str}"
        ).count()
        return f"SEC-{date_str}-{count+1:04d}"

    def save(self, *args, **kwargs):
        """
        Переопределённый метод сохранения.

        Автоматически генерирует номер протокола, если он не был задан.
        """
        if not self.protocol_number:
            self.protocol_number = self.generate_protocol_number()
        super().save(*args, **kwargs)


class SecurityFinding(models.Model):
    """
    Модель находки безопасности.

    Содержит информацию о конкретном выявленном нарушении
    в ходе проверки безопасности.

    Attributes:
        protocol (ForeignKey): Ссылка на протокол тестирования
        resource_name (CharField): Наименование проверяемого ресурса
        resource_type (CharField): Тип ресурса (storage, iam, service и т.д.)
        severity (CharField): Уровень критичности нарушения
        finding_message (TextField): Описание выявленного нарушения
        remediation (TextField): Рекомендации по устранению
        responsibility (CharField): Зона ответственности
        detection_time (DateTimeField): Время обнаружения нарушения
        resolved (BooleanField): Флаг устранения нарушения
        resolution_date (DateTimeField): Дата устранения (если resolved=True)
    """
    SEVERITY_LEVELS = [
        ('CRITICAL', 'Критический'),
        ('HIGH', 'Высокий'),
        ('MEDIUM', 'Средний'),
        ('WARNING', 'Предупреждение'),
        ('INFO', 'Информационный'),
    ]

    RESPONSIBILITY = [
        ('provider', 'Поставщик'),
        ('consumer', 'Потребитель'),
        ('shared', 'Совместная'),
    ]

    protocol = models.ForeignKey(
        TestProtocol,
        on_delete=models.CASCADE,
        related_name='findings',
        verbose_name="Протокол"
    )
    resource_name = models.CharField(
        max_length=200,
        verbose_name="Ресурс"
    )
    resource_type = models.CharField(
        max_length=50,
        verbose_name="Тип ресурса"
    )
    severity = models.CharField(
        max_length=20,
        choices=SEVERITY_LEVELS,
        verbose_name="Критичность"
    )
    finding_message = models.TextField(
        verbose_name="Описание находки"
    )
    remediation = models.TextField(
        verbose_name="Рекомендации по устранению"
    )
    responsibility = models.CharField(
        max_length=20,
        choices=RESPONSIBILITY,
        verbose_name="Ответственность"
    )
    detection_time = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Время обнаружения"
    )
    resolved = models.BooleanField(
        default=False,
        verbose_name="Устранено"
    )
    resolution_date = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Дата устранения"
    )

    class Meta:
        verbose_name = "Находка безопасности"
        verbose_name_plural = "Находки безопасности"
        ordering = ['-severity', '-detection_time']

    def __str__(self):
        """Строковое представление объекта."""
        return f"[{self.severity}] {self.resource_name}: {self.finding_message[:50]}"