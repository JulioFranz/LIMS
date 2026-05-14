from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0004_alter_profilechangetoken_new_value'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='totp_enabled',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='totp_secret',
            field=models.CharField(blank=True, default='', max_length=512),
        ),
    ]
