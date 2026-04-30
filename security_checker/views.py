# Представления (views) приложения security_checker

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .security_logic import SecurityChecker, calculate_metrics, create_visualization
from .models import CloudProvider, SecurityProtocol

def index(request):
    # Временная отладка протокола
    print("=== ОТЛАДКА ПРОТОКОЛА ===")
    print(f"request.is_secure() = {request.is_secure()}")
    print(f"HTTP_X_FORWARDED_PROTO = {request.META.get('HTTP_X_FORWARDED_PROTO', 'отсутствует')}")
    print(f"REQUEST_SCHEME = {request.scheme}")
    ...

# Основная страница проверки, доступна только авторизованным пользователям
@login_required
def index(request):
    """Главная страница с формой проверки и результатами."""
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
        metrics = calculate_metrics(findings)
        create_visualization(metrics)  # заглушка для графиков

        # Сохраняем протокол проверки, если были выбраны облако или протоколы
        if cloud_id or protocol_ids:
            checker.save_protocol(metrics)

        # Генерация HTML для списка находок
        findings_html = ""
        for finding in metrics.get("findings", []):
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
            'metrics': metrics,
            'findings_html': findings_html,
            'has_results': True,
            'selected_cloud': int(cloud_id) if cloud_id else None,
            'selected_protocols': [int(p) for p in protocol_ids],
        })
    else:
        context['has_results'] = False

    return render(request, 'security_checker/index.html', context)