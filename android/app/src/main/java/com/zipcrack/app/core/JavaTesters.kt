package com.zipcrack.app.core

import net.lingala.zip4j.ZipFile
import net.lingala.zip4j.exception.ZipException
import org.apache.commons.compress.archivers.sevenz.SevenZFile
import org.apache.poi.poifs.crypt.Decryptor
import org.apache.poi.poifs.crypt.EncryptionInfo
import org.apache.poi.poifs.filesystem.POIFSFileSystem
import java.io.ByteArrayInputStream
import java.io.File
import java.util.zip.CRC32

/**
 * ZIP password check via zip4j (ZipCrypto + WinZip AES).
 */
class Zip4jPasswordTester(private val archiveFile: File) : PasswordTester {
    override fun test(password: String): Boolean {
        return try {
            ZipFile(archiveFile, password.toCharArray()).use { z ->
                if (!z.isValidZipFile) return false
                val buf = ByteArray(8192)
                var checked = 0
                for (h in z.fileHeaders) {
                    if (h.isDirectory) continue
                    val crc = CRC32()
                    var size = 0L
                    z.getInputStream(h).use { inp ->
                        while (true) {
                            val n = inp.read(buf)
                            if (n < 0) break
                            crc.update(buf, 0, n)
                            size += n
                        }
                    }
                    val expectedSize = h.uncompressedSize
                    if (expectedSize >= 0 && size != expectedSize) return false
                    // zip4j exposes CRC as long
                    val expectedCrc = h.crc and 0xffffffffL
                    if (expectedCrc != 0L && (crc.value != expectedCrc)) return false
                    checked++
                }
                checked > 0
            }
        } catch (_: ZipException) {
            false
        } catch (_: Exception) {
            false
        }
    }
}

/**
 * 7z password check via Apache Commons Compress.
 *
 * Important: a wrong password can still open the archive and yield empty reads
 * without throwing. Always verify uncompressed size and CRC when present.
 */
class SevenZPasswordTester(private val archiveFile: File) : PasswordTester {
    override fun test(password: String): Boolean {
        return try {
            SevenZFile.builder()
                .setFile(archiveFile)
                .setPassword(password.toCharArray())
                .get()
                .use { f ->
                    val buf = ByteArray(8192)
                    var checked = 0
                    var entry = f.nextEntry
                    while (entry != null) {
                        if (!entry.isDirectory) {
                            val crc = CRC32()
                            var size = 0L
                            while (true) {
                                val n = f.read(buf)
                                if (n < 0) break
                                crc.update(buf, 0, n)
                                size += n
                            }
                            val expectedSize = entry.size
                            if (expectedSize >= 0 && size != expectedSize) return false
                            val expectedCrc = entry.crcValue
                            if (expectedCrc != 0L && crc.value != expectedCrc) return false
                            // Wrong password can yield 0 bytes without throwing.
                            if (size == 0L && expectedSize > 0L) return false
                            checked++
                        }
                        entry = f.nextEntry
                    }
                    checked > 0
                }
        } catch (_: Exception) {
            false
        }
    }
}

/**
 * Password-protected Office files (docx/xlsx/pptx, and often encrypted doc/xls):
 * OLE Compound File with EncryptionInfo + EncryptedPackage (ECMA-376 agile/standard).
 *
 * Uses Apache POI [Decryptor.verifyPassword] — no need for Microsoft Word on device.
 * Crypto is expensive (e.g. AES-256 + SHA-512, many iterations); ~tens of attempts/s.
 */
class OfficePasswordTester(archiveFile: File) : PasswordTester {
    private val raw: ByteArray = archiveFile.readBytes()
    val modeLabel: String
    val detailLabel: String

    init {
        POIFSFileSystem(ByteArrayInputStream(raw)).use { fs ->
            val info = EncryptionInfo(fs)
            modeLabel = info.encryptionMode?.name ?: "office"
            val header = info.header
            detailLabel = buildString {
                append(modeLabel)
                try {
                    append(" · ")
                    append(header.cipherAlgorithm)
                    append(" · ")
                    append(header.hashAlgorithm)
                    append(" · ")
                    append(header.keySize)
                    append("-bit")
                } catch (_: Exception) {
                }
            }
            // Smoke: must be able to construct decryptor
            Decryptor.getInstance(info)
        }
    }

    override fun test(password: String): Boolean {
        return try {
            POIFSFileSystem(ByteArrayInputStream(raw)).use { fs ->
                val info = EncryptionInfo(fs)
                Decryptor.getInstance(info).verifyPassword(password)
            }
        } catch (_: Exception) {
            false
        }
    }
}
