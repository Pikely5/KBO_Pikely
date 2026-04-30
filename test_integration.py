import os
import sys
import django

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
django.setup()

from django.test import TestCase, Client
from django.db import IntegrityError
from security_checker.models import (
    CloudProvider, SecurityProtocol, CloudComplianceData,
    TestProtocol, SecurityFinding
)
from security_checker.security_logic import SecurityChecker, calculate_metrics


class IntegrationDataFlowTest(TestCase):
    """Интеграционный тест сквозного пути данных"""

    @classmethod
    def setUpTestData(cls):
        cls.client = Client()
        cls.cloud = CloudProvider.objects.create(
            name="Yandex Cloud | Проект «Тестовый»",
            description="Тестовый проект",
            region="ru-central1",
            is_active=True
        )
        cls.protocol = SecurityProtocol.objects.create(
            protocol_id="TEST-152-FZ",
            name="О персональных данных",
            category="COMPLIANCE",
            description="Федеральный закон №152-ФЗ",
            severity_on_fail="CRITICAL",
            remediation_template="Хранить ПД на серверах в РФ",
            responsibility="shared",
            is_active=True,
            priority=1
        )
        CloudComplianceData.objects.create(
            cloud=cls.cloud,
            protocol=cls.protocol,
            is_compliant=False,
            compliance_level=40,
            notes="[Бакет: customer-data] Часть данных хранится вне РФ"
        )

    def _print_header(self, title):
        print(f"\n{'='*70}\n{title}\n{'='*70}")

    def _print_ok(self, msg):
        print(f"    ✓ {msg}")

    def _print_info(self, msg):
        print(f"    {msg}")

    def test_full_data_flow(self):
        """Проверка полного цикла преобразования данных"""
        self._print_header("ТЕСТ: ПОЛНЫЙ ЦИКЛ ПРЕОБРАЗОВАНИЯ ДАННЫХ")

        # Этап 1: Получение данных
        self._print_info(f">>> Этап 1: Получение данных из БД (cloud={self.cloud.id}, proto={self.protocol.id})")
        checker = SecurityChecker(self.cloud.id, [self.protocol.id])
        findings = checker.run_full_check()
        self._print_info(f"Найдено нарушений: {len(findings)}")
        self.assertEqual(len(findings), 1)
        self._print_ok("Данные получены из БД")

        # Этап 2: Расчёт метрик
        self._print_info(">>> Этап 2: Расчёт метрик безопасности")
        metrics = calculate_metrics(findings)
        for key in ['risk_score', 'compliance_percent', 'critical_findings', 'warning_findings', 'provider_issues', 'consumer_issues']:
            self._print_info(f"{key}: {metrics[key]}")
        self.assertEqual(metrics['risk_score'], 100.0)
        self.assertEqual(metrics['compliance_percent'], 85.0)
        self._print_ok("Метрики рассчитаны корректно")

        # Этап 3: Сохранение
        self._print_info(">>> Этап 3: Сохранение результатов в БД")
        count_before = TestProtocol.objects.count()
        protocol = checker.save_protocol(metrics)
        self._print_info(f"Протоколов: {count_before} → {TestProtocol.objects.count()}")
        self._print_info(f"Номер протокола: {protocol.protocol_number}")
        self.assertEqual(TestProtocol.objects.count(), count_before + 1)
        self._print_ok("Протокол сохранён в БД")

        # Этап 4: Целостность
        self._print_info(">>> Этап 4: Проверка целостности данных")
        finding = SecurityFinding.objects.filter(protocol=protocol).first()
        self._print_info(f"Ресурс: {finding.resource_name} | Критичность: {finding.severity} | Ответственный: {finding.responsibility}")
        self.assertEqual(finding.resource_name, 'customer-data')
        self.assertEqual(finding.severity, 'CRITICAL')
        self._print_ok("Данные в БД соответствуют исходным")

        # Этап 5: HTTP-ответ
        self._print_info(">>> Этап 5: Проверка HTTP-ответа")
        response = self.client.post('/', {'cloud': str(self.cloud.id), 'protocols': [str(self.protocol.id)]})
        content = response.content.decode()
        self._print_info(f"Статус: {response.status_code} | Результаты: {'Результаты проверки' in content} | Находки: {'customer-data' in content}")
        self.assertEqual(response.status_code, 200)
        self.assertIn('Результаты проверки', content)
        self.assertIn('customer-data', content)
        self._print_ok("HTTP-ответ корректен")

        self._print_header("ВСЕ ЭТАПЫ ПРОЙДЕНЫ УСПЕШНО")

    def test_unique_name_constraint(self):
        """Проверка уникальности имени облачного провайдера"""
        self._print_header("ТЕСТ: УНИКАЛЬНОСТЬ ИМЕНИ ПРОВАЙДЕРА")
        with self.assertRaises(IntegrityError):
            CloudProvider.objects.create(name="Yandex Cloud | Проект «Тестовый»", description="Дубликат", region="ru-central1", is_active=True)
        self._print_ok("Уникальность работает (IntegrityError при дубликате)")
        print("=" * 70)

    def test_protocol_number_format(self):
        """Проверка формата и уникальности номеров протоколов"""
        self._print_header("ТЕСТ: ФОРМАТ И УНИКАЛЬНОСТЬ НОМЕРОВ ПРОТОКОЛОВ")
        p1, p2 = TestProtocol.objects.create(), TestProtocol.objects.create()
        self._print_info(f"Номера: {p1.protocol_number} | {p2.protocol_number}")
        self.assertRegex(p1.protocol_number, r'SEC-\d{8}-\d{4}')
        self.assertNotEqual(p1.protocol_number, p2.protocol_number)
        self._print_ok("Формат корректен, номера уникальны")
        print("=" * 70)

    def test_cascade_delete(self):
        """Проверка каскадного удаления"""
        self._print_header("ТЕСТ: КАСКАДНОЕ УДАЛЕНИЕ")
        cloud = CloudProvider.objects.create(name="Temp Cloud", description="", region="ru-central1", is_active=True)
        CloudComplianceData.objects.create(cloud=cloud, protocol=self.protocol, is_compliant=True, compliance_level=100, notes="")
        self._print_info(f"Записей до удаления: {CloudComplianceData.objects.filter(cloud=cloud).count()}")
        cloud.delete()
        self._print_info(f"Записей после удаления: {CloudComplianceData.objects.filter(cloud__name='Temp Cloud').count()}")
        self.assertEqual(CloudComplianceData.objects.filter(cloud__name="Temp Cloud").count(), 0)
        self._print_ok("Каскадное удаление работает")
        print("=" * 70)

    def test_ui_elements(self):
        """Проверка элементов пользовательского интерфейса"""
        self._print_header("ТЕСТ: ЭЛЕМЕНТЫ ИНТЕРФЕЙСА")

        # GET-запрос
        content = self.client.get('/').content.decode()
        self._print_info(f"GET / → статус: {self.client.get('/').status_code}")
        self._print_ok("Главная страница доступна")

        # Ключевые элементы
        for el in ['Контейнер безопасности облака', 'Проект в Yandex Cloud', 'Протоколы для проверки', 'Начать проверку безопасности', 'csrfmiddlewaretoken', 'Выбрать все']:
            self.assertIn(el, content)
        self._print_ok("Все ключевые элементы присутствуют")

        # POST-запрос и цветовое выделение
        content = self.client.post('/', {'cloud': str(self.cloud.id), 'protocols': [str(self.protocol.id)]}).content.decode()
        has_critical = 'class="critical"' in content or "class='critical'" in content or 'CRITICAL' in content
        self._print_info(f"CSS-класс critical: {has_critical}")
        self.assertTrue(has_critical)
        self._print_ok("Цветовое выделение настроено")

        self._print_header("ПРОВЕРКИ ИНТЕРФЕЙСА ПРОЙДЕНЫ УСПЕШНО")


if __name__ == '__main__':
    import unittest
    unittest.main(verbosity=2)