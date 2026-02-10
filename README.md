#TURN OFF:
How to Stop the Service:
To stop the service, users must:
1.	Open Command Prompt as Administrator
2.	Set the environment variable: `setx SECURE_OVERRIDE true`
3.	Stop the service via Services.msc or `net stop SecureYourWifi`
4.	(Optional) Clear the override: `setx SECURE_OVERRIDE ""`
