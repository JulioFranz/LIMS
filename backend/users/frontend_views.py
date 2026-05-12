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


def password_reset_request_page(request):
    return render(request, 'password_reset_request.html')


def password_reset_confirm_page(request):
    # uid e token chegam via query string (?uid=...&token=...)
    return render(request, 'password_reset_confirm.html', {
        'uid': request.GET.get('uid', ''),
        'token': request.GET.get('token', ''),
    })