# Encrypted password CLI

ใช้ Python 3.10+ และติดตั้งไลบรารี:

```powershell
python -m pip install -r requirements.txt
python Encrypt.py encrypt encrypted_google_password.json --hint "MyFavQ"
python Encrypt.py decrypt encrypted_google_password.json
```

หากเครื่องใช้คำสั่ง `py` ให้แทน `python` ด้วย `py` ได้
ใน workspace นี้ติดตั้งไลบรารีใน `.venv` แล้ว ใช้ `.\.venv\Scripts\python.exe` แทน `python` ได้ทันที

รับ password และ master passphrase แบบซ่อน ไม่ส่ง secrets ผ่าน arguments
ยืนยัน master passphrase ก่อนบันทึก และไม่เขียนทับไฟล์ที่มีอยู่
ใช้ master passphrase ที่สุ่มจริง 4–6 คำขึ้นไป อย่าใช้ตัวอย่างนี้เป็นความลับของคุณ
Argon2id เพิ่มต้นทุนการเดา แต่ไม่ทำให้ passphrase ที่เดาง่ายปลอดภัย

บน Windows การถอดรหัสจะคัดลอก password ไปยัง clipboard และรอ 30 วินาทีก่อนล้าง
ถ้าคัดลอกข้อความใหม่ โปรแกรมจะไม่ล้างข้อความใหม่ กด Ctrl+C เพื่อล้างทันที
Clipboard history, cloud sync และโปรแกรมอื่นอาจเก็บสำเนา: ปิด history/sync หากใช้วิธีนี้
หากปิดโปรแกรมก่อนหมดเวลา การล้าง clipboard อาจไม่สำเร็จ
หากยอมรับให้ password ค้างใน terminal ใช้ `--show`:

```powershell
python Encrypt.py decrypt encrypted_google_password.json --show
python Decrypt.py encrypted_google_password.json
```

JSON เก็บ version, KDF parameters, public hint, salt, nonce และ ciphertext
AES-GCM รวม authentication tag ใน ciphertext และตรวจ header/hint ด้วย AAD
Argon2id ใช้ 64 MiB, time cost 3, parallelism 4 และ key 32 bytes
สุ่ม salt 16 bytes และ nonce 12 bytes ใหม่ทุกครั้ง
อ่านไฟล์จากโค้ดเดิมที่มีเพียง salt/nonce/ciphertext ได้ด้วย parameters เดิม

เก็บไฟล์สำรองได้ แต่แยก master passphrase และ recovery codes ออกจากไฟล์
Hint เปิดเผยต่อผู้อื่นได้ จึงไม่ควรบอกคำใน passphrase โดยตรง
หากลืม master passphrase จะกู้ plaintext จากไฟล์นี้ไม่ได้
โปรแกรมไม่ป้องกันมัลแวร์ และ Python ไม่รับประกันการลบ secrets จาก memory

ทดสอบด้วย `python -m unittest -v` (ใช้ข้อมูลจำลองเท่านั้น)