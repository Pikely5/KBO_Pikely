# Представления для аутентификации пользователей

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import AuthenticationForm

def login_view(request):
    """Обработка входа пользователя."""
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            # Перенаправление на запрашиваемую страницу или на главную
            next_url = request.GET.get('next', '/')
            return redirect(next_url)
    else:
        form = AuthenticationForm()

    return render(request, 'security_checker/login.html', {'form': form})

def logout_view(request):
    """Выход пользователя из системы."""
    logout(request)
    return render(request, 'security_checker/logged_out.html')