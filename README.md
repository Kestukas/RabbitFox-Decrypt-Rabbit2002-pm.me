# RabbitFox-Decrypt-Rabbit2002-pm.me
Decryptor for similar Ransomware as RabbitFox Rabbit2002@pm.me (idea)

Identified by
ransomnote_email: Rabbit2002@pm.me
sample_extension: id <id>[Rabbit2002@pm.me].fox
  
Video tutorial : https://youtu.be/1hI7YDCPgt4

This is my sample application how i decrypted most  of my files.

It does not analyde encryptof itself , because i do not analyzed virus file.

This is idea how to fix your files , without having virus file to analyze.

my email address is tumelis.k@gmail.com for questions.

There is 3 different ways to use this application .

1. Since virus is encrypting 10 first bytes of a file, you simply make a list of signatures in Configuration.ini example :

[Ext]
xlsx = 504B0304140006000800
lnk = 4C000000011402000000
zip = 504B0304140000000800
pdf = 255044462D312E370A0A
exe = 4D5A9000030000000400
xls = D0CF11E0A1B11AE10000
jpg = FFD8FFE000104A464946
png = 89504E470D0A1A0A0000
rar = 526172211A0700CF9073
doc = D0CF11E0A1B11AE10000
docx = 504B0304140006000800

and when app finds that you have for Example *.ZIP file it overwrites first bytes and you have working files.

2. Second option is by using a comparisement , if you have like unique files for example a991.dat that is unique because other aapsz_a.dat has other signature, you can add it in UniqueFiles.ini for example :
banexp.dat = A5166592E07DDF78E0DF
bankas.dat = 4333A600E205E0EFE05A


3. Third is most advanced way , if you have some sort of backups, of you have alot files that have alternatives for example dll, exe, some text files that you have backups from , you can make a dictionary for 10 bytes.

it will be placed in : hex.ini

program has scanner function to put this values by adding all files to one directory.

it will take something like :
[BYTE01]
30 = 43
[BYTE02]
5E = 3A

that means that it found 2 files  "banexp.dat" and "banexp.dat id 1720406111[Rabbit2002@pm.me].fox" that has same size, and made a translation that byte 01 encripted is 30 and its decrypted byte is 43.

so if you have huge ammount of such files , you can make really nice dictionary that will decrypt all your custom files if you dont have dictionary for it.


