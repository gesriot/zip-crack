package com.zipcrack.app.core

import org.apache.commons.compress.archivers.sevenz.SevenZFile
import org.apache.poi.poifs.crypt.EncryptionInfo
import org.apache.poi.poifs.filesystem.POIFSFileSystem
import java.io.ByteArrayInputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Detect archive type / encryption and choose backend.
 * No native 7zz — Linux glibc binaries get SIGSYS on Android.
 */
object ArchiveProbe {
    private const val SIG_LOCAL = 0x04034b50
    private const val SIG_CENTRAL = 0x02014b50
    private const val SIG_EOCD = 0x06054b50
    private val SIG_7Z = byteArrayOf(0x37, 0x7a, 0xbc.toByte(), 0xaf.toByte(), 0x27, 0x1c)
    private val SIG_OLE = byteArrayOf(
        0xd0.toByte(), 0xcf.toByte(), 0x11.toByte(), 0xe0.toByte(),
        0xa1.toByte(), 0xb1.toByte(), 0x1a.toByte(), 0xe1.toByte(),
    )

    fun probe(raw: ByteArray, displayName: String, workDir: File): ArchiveInfo {
        return when {
            isOle(raw) -> probeOffice(raw, displayName, workDir)
            is7z(raw) -> probe7z(raw, displayName, workDir)
            isZip(raw) -> probeZip(raw, displayName, workDir)
            else -> throw ZipCrackException(
                "неизвестный формат. Поддерживаются ZIP, 7z, encrypted DOCX/XLSX (Office)."
            )
        }
    }

    private fun probeOffice(raw: ByteArray, displayName: String, workDir: File): ArchiveInfo {
        val path = writeTemp(raw, workDir, displayName)
        // Confirm EncryptionInfo exists and POI can parse it.
        val detail = try {
            POIFSFileSystem(ByteArrayInputStream(raw)).use { fs ->
                val has =
                    fs.root.hasEntry(EncryptionInfo.ENCRYPTION_INFO_ENTRY) ||
                        fs.root.hasEntry("EncryptionInfo")
                if (!has) {
                    throw ZipCrackException(
                        "OLE/Compound файл без EncryptionInfo — это не password-encrypted Office " +
                            "(обычный .doc/.xls или незашифрованный контейнер)."
                    )
                }
                val info = EncryptionInfo(fs)
                val mode = info.encryptionMode?.name ?: "office"
                val header = info.header
                "$mode · ${header.cipherAlgorithm} · ${header.hashAlgorithm} · ${header.keySize}-bit"
            }
        } catch (e: ZipCrackException) {
            throw e
        } catch (e: Exception) {
            throw ZipCrackException("не удалось прочитать Office EncryptionInfo: ${e.message}")
        }

        val ext = displayName.substringAfterLast('.', "").lowercase()
        val kind = when (ext) {
            "docx", "docm", "dotx", "dotm" -> "Word"
            "xlsx", "xlsm", "xltx", "xltm", "xlsb" -> "Excel"
            "pptx", "pptm", "potx", "potm" -> "PowerPoint"
            "doc", "xls", "ppt" -> "Office legacy"
            else -> "Office"
        }

        return ArchiveInfo(
            displayName = displayName,
            typeLabel = "$kind · $detail",
            backend = CrackBackend.JAVA_OFFICE,
            slowPath = true,
            warning = "Office encryption (POI): ~десятки попыток/с (SHA/AES iterations). " +
                "Word на устройстве не требуется.",
            archivePath = path,
        )
    }

    private fun probeZip(raw: ByteArray, displayName: String, workDir: File): ArchiveInfo {
        val scan = scanZipEncryption(raw)
        when (scan.kind) {
            ZipEncKind.NONE -> throw ZipCrackException("ZIP не защищён паролем")
            ZipEncKind.ZIPCRYPTO -> {
                val z = ZipArchive.open(raw)
                return ArchiveInfo(
                    displayName = displayName,
                    typeLabel = "ZIP · ZipCrypto",
                    backend = CrackBackend.NATIVE_ZIPCRYPTO,
                    slowPath = false,
                    warning = null,
                    zipCrypto = z,
                )
            }
            ZipEncKind.AES, ZipEncKind.MIXED -> {
                val path = writeTemp(raw, workDir, displayName)
                val label = if (scan.kind == ZipEncKind.MIXED) {
                    "ZIP · AES + ZipCrypto"
                } else {
                    "ZIP · AES-${scan.aesBits ?: "?"}"
                }
                return ArchiveInfo(
                    displayName = displayName,
                    typeLabel = label,
                    backend = CrackBackend.JAVA_ZIP,
                    slowPath = true,
                    warning = "AES (zip4j): каждая попытка расшифровывает запись — медленнее ZipCrypto.",
                    archivePath = path,
                )
            }
        }
    }

    private fun probe7z(raw: ByteArray, displayName: String, workDir: File): ArchiveInfo {
        val path = writeTemp(raw, workDir, displayName)
        // Only "nextEntry" is not enough: content-encrypted 7z often lists entries
        // without a password, then fails (or yields empty data) on read.
        if (sevenZFullyReadableWithoutPassword(File(path))) {
            throw ZipCrackException("7z-архив не защищён паролем (или пуст)")
        }
        return ArchiveInfo(
            displayName = displayName,
            typeLabel = "7z · AES",
            backend = CrackBackend.JAVA_7Z,
            slowPath = true,
            warning = "7z AES (Commons Compress): перебор медленнее native ZipCrypto.",
            archivePath = path,
        )
    }

    /**
     * True only if every file entry can be fully decompressed without a password
     * and sizes match. Otherwise treat as password-protected.
     */
    private fun sevenZFullyReadableWithoutPassword(file: File): Boolean {
        return try {
            SevenZFile.builder().setFile(file).get().use { f ->
                val buf = ByteArray(8192)
                var files = 0
                var entry = f.nextEntry
                while (entry != null) {
                    if (!entry.isDirectory) {
                        var size = 0L
                        while (true) {
                            val n = f.read(buf)
                            if (n < 0) break
                            size += n
                        }
                        if (entry.size >= 0 && size != entry.size) return false
                        if (size == 0L && entry.size > 0L) return false
                        files++
                    }
                    entry = f.nextEntry
                }
                files > 0
            }
        } catch (_: Exception) {
            false
        }
    }

    private enum class ZipEncKind { NONE, ZIPCRYPTO, AES, MIXED }

    private data class ZipScan(val kind: ZipEncKind, val aesBits: Int?)

    private fun scanZipEncryption(raw: ByteArray): ZipScan {
        val eocd = findEocd(raw) ?: return ZipScan(ZipEncKind.NONE, null)
        val cdOff = u32(raw, eocd + 16)
        val nEntries = u16(raw, eocd + 10)
        var pos = cdOff
        var zipCrypto = false
        var aes = false
        var aesBits: Int? = null

        for (i in 0 until nEntries) {
            if (pos + 46 > raw.size) break
            if (u32(raw, pos) != SIG_CENTRAL) break
            val flags = u16(raw, pos + 8)
            val method = u16(raw, pos + 10)
            val nameLen = u16(raw, pos + 28)
            val extraLen = u16(raw, pos + 30)
            val commentLen = u16(raw, pos + 32)
            val extraStart = pos + 46 + nameLen
            val encrypted = flags and 0x1 != 0
            if (encrypted) {
                if (method == 99) {
                    aes = true
                    aesBits = parseAesBits(raw, extraStart, extraLen) ?: aesBits
                } else {
                    zipCrypto = true
                }
            }
            pos += 46 + nameLen + extraLen + commentLen
        }

        val kind = when {
            aes && zipCrypto -> ZipEncKind.MIXED
            aes -> ZipEncKind.AES
            zipCrypto -> ZipEncKind.ZIPCRYPTO
            else -> ZipEncKind.NONE
        }
        return ZipScan(kind, aesBits)
    }

    private fun parseAesBits(raw: ByteArray, extraStart: Int, extraLen: Int): Int? {
        var p = extraStart
        val end = extraStart + extraLen
        while (p + 4 <= end && p + 4 <= raw.size) {
            val id = u16(raw, p)
            val sz = u16(raw, p + 2)
            p += 4
            if (p + sz > raw.size) break
            if (id == 0x9901 && sz >= 7) {
                val strength = raw[p + 4].toInt() and 0xff
                return when (strength) {
                    1 -> 128
                    2 -> 192
                    3 -> 256
                    else -> null
                }
            }
            p += sz
        }
        return 256
    }

    private fun is7z(raw: ByteArray): Boolean {
        if (raw.size < 6) return false
        for (i in SIG_7Z.indices) if (raw[i] != SIG_7Z[i]) return false
        return true
    }

    private fun isOle(raw: ByteArray): Boolean {
        if (raw.size < 8) return false
        for (i in SIG_OLE.indices) if (raw[i] != SIG_OLE[i]) return false
        return true
    }

    private fun isZip(raw: ByteArray): Boolean {
        if (raw.size < 4) return false
        val sig = u32(raw, 0)
        return sig == SIG_LOCAL || sig == SIG_CENTRAL || sig == SIG_EOCD || sig == 0x08074b50
    }

    private fun findEocd(raw: ByteArray): Int? {
        if (raw.size < 22) return null
        val start = raw.size - 22
        val limit = maxOf(0, raw.size - (22 + 65535))
        for (i in start downTo limit) {
            if (u32(raw, i) == SIG_EOCD) return i
        }
        return null
    }

    private fun writeTemp(raw: ByteArray, workDir: File, displayName: String): String {
        workDir.mkdirs()
        val safe = displayName.replace(Regex("[^A-Za-z0-9._-]"), "_").ifEmpty { "archive" }
        val f = File(workDir, "input_$safe")
        f.writeBytes(raw)
        return f.absolutePath
    }

    private fun u16(b: ByteArray, off: Int): Int =
        ByteBuffer.wrap(b, off, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xffff

    private fun u32(b: ByteArray, off: Int): Int =
        ByteBuffer.wrap(b, off, 4).order(ByteOrder.LITTLE_ENDIAN).int
}
