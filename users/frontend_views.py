from django.shortcuts import render


def login_page(request):
    return render(request, 'login.html')


def register_page(request):
    return render(request, 'register.html')


def verify_2fa_page(request):
    return render(request, 'verify_2fa.html')


def verify_email_page(request):
    return render(request, 'verify_email.html')


def dashboard_page(request):
    return render(request, 'dashboard.html')
