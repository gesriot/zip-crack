Native 7zzs was removed: the official Linux arm64 static binary aborts on Android
with SIGSYS (seccomp) and cannot be exec'd from app filesDir (EACCES).

AES ZIP and 7z are handled in pure Java:
  - net.lingala.zip4j (ZIP ZipCrypto + AES)
  - org.apache.commons:commons-compress (7z AES)
