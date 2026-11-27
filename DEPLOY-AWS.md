# פריסה ל-AWS תל אביב (il-central-1)

ארכיטקטורה: CloudFront (CDN) ← S3 (האתר) + API Gateway ← Lambda ← DynamoDB. הכול בישראל חוץ מה-CDN וה-certificate (ראו הערה).

## דרישות
- חשבון AWS, AWS CLI v2 ו-SAM CLI מותקנים; `aws configure` עם משתמש IAM עם הרשאות לפריסה.
- אזור: il-central-1 (נבחר אוטומטית ב-deploy.sh). אם האזור לא מופעל בחשבון – להפעיל אותו (Opt-in) בהגדרות Account → AWS Regions.

## פריסה ראשונה (בלי דומיין)
```
./deploy.sh
```
בסוף מודפסת כתובת `https://xxxx.cloudfront.net` – האתר כבר עובד שם, כולל שמירת משתמשים והתקדמות.

## חיבור הדומיין yao.co.il
1. ב-ACM באזור **us-east-1** (CloudFront דורש זאת) מבקשים certificate ל-`yao.co.il` ול-`www.yao.co.il` (אימות DNS).
2. מריצים:
```
DOMAIN=yao.co.il CERT_ARN=arn:aws:acm:us-east-1:... ALERT_EMAIL=you@example.com ./deploy.sh
```
3. ב-DNS: `www` ← CNAME לכתובת `*.cloudfront.net` שהודפסה. לשורש (yao.co.il) צריך ALIAS/ANAME – ב-Cloudflare DNS זה CNAME flattening אוטומטי (מומלץ להעביר אליו את ה-DNS), או להעביר ל-Route 53.

## עדכון האתר
עורכים `index.html` ומריצים שוב `./deploy.sh`.

## נתונים ופרטיות
- DynamoDB: משתמש + קוד 4 ספרות מוצפן (scrypt), כוכבים, יומן אחרון (300 רשומות) ומילים שטעו בהן. גיבוי PITR פעיל והטבלה לא נמחקת עם מחיקת ה-stack.
- הגנה: נעילה ל-5 דקות אחרי 5 ניסיונות כושלים, הגבלת קצב ב-API. קוד של 4 ספרות הוא הגנה בסיסית בלבד, מתאים לילדים ולא למידע רגיש.
- לפני שימוש עם ילדים מעבר למשפחה: מדיניות פרטיות, הסכמת הורים, וייתכן חובת רישום מאגר מידע – מומלץ לבדוק מול יועץ פרטיות.
- מחיקת משתמש: `aws dynamodb delete-item --table-name <TableName> --key '{"user":{"S":"שם"}}' --region il-central-1`

## עלות משוערת
תעבורה קטנה: בערך 1–3 דולר בחודש (CloudFront/S3/Lambda/DynamoDB on-demand הם כמעט בחינם בנפח כזה; הדומיין וה-certificate ללא עלות נוספת). התראת תקציב נוצרת אם מציינים ALERT_EMAIL.

## הערה על מיקום
S3, Lambda ו-DynamoDB (כל הנתונים) יושבים בתל אביב. CloudFront הוא שירות גלובלי שמשרת מ-edge קרוב למשתמש (בישראל יש edge), ו-ACM ל-CloudFront חייב להיות ב-us-east-1 (אין שם נתוני משתמשים).

## הרצה מקומית לבדיקה
`node backend/handler.test.mjs`
