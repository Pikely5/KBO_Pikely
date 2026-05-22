# Представления (views) приложения security_checker

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from .security_logic import SecurityChecker, calculate_metrics, create_visualization
from .models import CloudProvider, SecurityProtocol

# Импорт метрик Prometheus (Histogram временно отключён из-за ошибки меток)
from prometheus_client import Counter, Gauge, generate_latest, REGISTRY

# ============================================================
# Определение метрик Prometheus
# ============================================================

# Счётчик HTTP-запросов (метод, эндпоинт)
REQUESTS = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint'])

# Датчики для метрик безопасности
RISK_SCORE = Gauge('risk_score', 'Current risk score (0-100)')
COMPLIANCE_PERCENT = Gauge('compliance_percent', 'Current compliance percent (0-100)')
CRITICAL_FINDINGS = Gauge('critical_findings', 'Number of critical findings')
WARNING_FINDINGS = Gauge('warning_findings', 'Number of warning findings')

# Датчик статуса контейнера (1 - работает, 0 - не работает)
CONTAINER_UP = Gauge('container_up', 'Container health status')

# ============================================================
# Эндпоинт для сбора метрик Prometheus
# ============================================================

def metrics(request):
    """Эндпоинт /metrics для сбора метрик Prometheus."""
    CONTAINER_UP.set(1)
    return HttpResponse(generate_latest(REGISTRY), content_type="text/plain")

# ============================================================
# Основная страница проверки (только для авторизованных)
# ============================================================

@login_required
def index(request):
    """Главная страница с формой проверки и результатами."""
    
    # Инкрементируем счётчик запросов
    REQUESTS.labels(method=request.method, endpoint='/').inc()
    
    # Получаем активные облачные проекты, исключая корневой Yandex Cloud
    clouds = CloudProvider.objects.filter(is_active=True).exclude(name="Yandex Cloud")
    protocols = SecurityProtocol.objects.filter(is_active=True)

    context = {
        'title': 'Контейнер безопасности облака - Вариант 32',
        'author': 'Петров Виктор',
        'clouds': clouds,
        'protocols': protocols,
    }

    if request.method == 'POST':
        # Получение параметров из формы
        cloud_id = request.POST.get('cloud')
        protocol_ids = request.POST.getlist('protocols')

        # Инициализация проверки
        checker = SecurityChecker(cloud_id=cloud_id, protocol_ids=protocol_ids)
        findings = checker.run_full_check()
        metrics_data = calculate_metrics(findings)
        create_visualization(metrics_data)  # заглушка для графиков

        # Обновляем датчики Prometheus актуальными значениями
        RISK_SCORE.set(metrics_data.get('risk_score', 0))
        COMPLIANCE_PERCENT.set(metrics_data.get('compliance_percent', 0))
        CRITICAL_FINDINGS.set(metrics_data.get('critical_findings', 0))
        WARNING_FINDINGS.set(metrics_data.get('warning_findings', 0))

        # Сохраняем протокол проверки, если были выбраны облако или протоколы
        if cloud_id or protocol_ids:
            checker.save_protocol(metrics_data)

        # Генерация HTML для списка находок
        findings_html = ""
        for finding in metrics_data.get("findings", []):
            severity_class = "critical" if finding.get("severity") == "CRITICAL" else "warning"
            responsible_text = "Потребитель" if finding.get("responsible") == "consumer" else "Поставщик"
            findings_html += f"""
            <li class='{severity_class}'>
                <strong>[{finding.get('severity')}]</strong> {finding.get('resource')}: {finding.get('message')}<br>
                <small>Рекомендация: {finding.get('remediation')} | Ответственный: {responsible_text}</small>
            </li>
            """

        # Дополняем контекст результатами
        context.update({
            'metrics': metrics_data,
            'findings_html': findings_html,
            'has_results': True,
            'selected_cloud': int(cloud_id) if cloud_id else None,
            'selected_protocols': [int(p) for p in protocol_ids],
        })
    else:
        context['has_results'] = False

    return render(request, 'security_checker/index.html', context)