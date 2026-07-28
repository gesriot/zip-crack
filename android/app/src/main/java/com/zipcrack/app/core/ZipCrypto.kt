package com.zipcrack.app.core

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.CRC32
import java.util.zip.Inflater

class ZipCrackException(message: String) : Exception(message)

/** One encrypted ZipCrypto entry (ciphertext kept for CRC verification). */
class ZipTarget(
    val method: Int,
    val crc32: Long,
    val uncomp: Long,
    val encHeader: ByteArray, // 12 bytes
    val checkByte: Int,
    val data: ByteArray,
)

class ZipArchive(val targets: List<ZipTarget>) {
    fun testPassword(password: String): Boolean {
        if (targets.isEmpty()) return false
        if (!verifyTarget(password, targets[0])) return false
        for (i in 1 until targets.size) {
            if (!verifyTarget(password, targets[i])) return false
        }
        return true
    }

    companion object {
        private const val SIG_LOCAL = 0x04034b50
        private const val SIG_CENTRAL = 0x02014b50
        private const val SIG_EOCD = 0x06054b50

        fun open(raw: ByteArray): ZipArchive {
            val eocd = findEocd(raw)
            val cdOff = u32(raw, eocd + 16)
            val cdSize = u32(raw, eocd + 12)
            val nEntries = u16(raw, eocd + 10)
            if (cdOff.toLong() + cdSize > raw.size) {
                throw ZipCrackException("не ZIP: central directory за пределами файла")
            }

            val targets = ArrayList<ZipTarget>()
            var pos = cdOff
            for (i in 0 until nEntries) {
                if (pos + 46 > raw.size) break
                if (u32(raw, pos) != SIG_CENTRAL) {
                    throw ZipCrackException("не ZIP: битый central directory")
                }
                val flags = u16(raw, pos + 8)
                val method = u16(raw, pos + 10)
                val modTime = u16(raw, pos + 12)
                val crc = u32(raw, pos + 16).toLong() and 0xffffffffL
                val compSize = u32(raw, pos + 20)
                val uncomp = u32(raw, pos + 24).toLong() and 0xffffffffL
                val nameLen = u16(raw, pos + 28)
                val extraLen = u16(raw, pos + 30)
                val commentLen = u16(raw, pos + 32)
                val localOff = u32(raw, pos + 42)
                pos += 46 + nameLen + extraLen + commentLen

                val encrypted = flags and 0x1 != 0
                if (!encrypted) continue
                // AES entries are handled via 7zz — skip here.
                if (method == 99) continue
                if (method != 0 && method != 8) {
                    throw ZipCrackException("метод сжатия $method не поддерживается в native-режиме")
                }
                if (compSize < 12) {
                    throw ZipCrackException("зашифрованная запись слишком короткая")
                }
                targets.add(
                    loadLocal(raw, localOff, method, crc, uncomp, modTime, flags, compSize)
                )
            }

            if (targets.isEmpty()) {
                if (nEntries == 0) throw ZipCrackException("ZIP пуст")
                throw ZipCrackException("нет ZipCrypto-записей для native-проверки")
            }
            targets.sortBy { it.data.size }
            return ZipArchive(targets)
        }

        private fun loadLocal(
            raw: ByteArray,
            off: Int,
            method: Int,
            crc: Long,
            uncomp: Long,
            modTime: Int,
            flags: Int,
            compSize: Int,
        ): ZipTarget {
            if (off < 0 || off + 30 > raw.size) {
                throw ZipCrackException("local header за пределами файла")
            }
            if (u32(raw, off) != SIG_LOCAL) {
                throw ZipCrackException("битый local header")
            }
            val nameLen = u16(raw, off + 26)
            val extraLen = u16(raw, off + 28)
            val dataStart = off + 30 + nameLen + extraLen
            val dataEnd = dataStart + compSize
            if (dataStart < 0 || dataEnd > raw.size || dataStart + 12 > raw.size) {
                throw ZipCrackException("payload за пределами файла")
            }
            val header = raw.copyOfRange(dataStart, dataStart + 12)
            val data = raw.copyOfRange(dataStart + 12, dataEnd)
            val checkByte = if (flags and 0x8 != 0) {
                (modTime shr 8) and 0xff
            } else {
                ((crc shr 24) and 0xff).toInt()
            }
            return ZipTarget(method, crc, uncomp, header, checkByte, data)
        }

        private fun findEocd(raw: ByteArray): Int {
            if (raw.size < 22) throw ZipCrackException("не ZIP-архив")
            val start = raw.size - 22
            val limit = maxOf(0, raw.size - (22 + 65535))
            for (i in start downTo limit) {
                if (u32(raw, i) == SIG_EOCD) return i
            }
            throw ZipCrackException("не ZIP-архив")
        }

        private fun u16(b: ByteArray, off: Int): Int =
            ByteBuffer.wrap(b, off, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xffff

        private fun u32(b: ByteArray, off: Int): Int =
            ByteBuffer.wrap(b, off, 4).order(ByteOrder.LITTLE_ENDIAN).int
    }
}

private class ZipKeys {
    var k0: Int = 0x12345678
    var k1: Int = 0x23456789
    var k2: Int = 0x34567890

    fun init(password: String) {
        k0 = 0x12345678
        k1 = 0x23456789
        k2 = 0x34567890
        for (ch in password) {
            update((ch.code and 0xff).toByte())
        }
    }

    fun update(c: Byte) {
        k0 = crc32Update(k0, c)
        k1 = (k1 + (k0 and 0xff)) * 134775813 + 1
        k2 = crc32Update(k2, ((k1 ushr 24) and 0xff).toByte())
    }

    fun decryptByte(): Int {
        val temp = (k2 or 2).toLong() and 0xffffffffL
        return (((temp * (temp xor 1)) ushr 8) and 0xff).toInt()
    }
}

private val CRC_TABLE: IntArray = IntArray(256).also { t ->
    for (i in 0 until 256) {
        var c = i
        repeat(8) {
            c = if (c and 1 != 0) 0xedb88320.toInt() xor (c ushr 1) else c ushr 1
        }
        t[i] = c
    }
}

private fun crc32Update(crc: Int, b: Byte): Int =
    CRC_TABLE[(crc xor (b.toInt() and 0xff)) and 0xff] xor (crc ushr 8)

private fun verifyTarget(password: String, t: ZipTarget): Boolean {
    val k = ZipKeys()
    k.init(password)
    var last = 0
    for (i in 0 until 12) {
        val c = (t.encHeader[i].toInt() and 0xff) xor k.decryptByte()
        k.update(c.toByte())
        last = c
    }
    if (last != t.checkByte) return false

    val plain = ByteArray(t.data.size)
    for (i in t.data.indices) {
        val c = (t.data[i].toInt() and 0xff) xor k.decryptByte()
        k.update(c.toByte())
        plain[i] = c.toByte()
    }

    val body: ByteArray = when (t.method) {
        0 -> plain
        8 -> {
            try {
                inflateRaw(plain, t.uncomp)
            } catch (_: Exception) {
                return false
            }
        }
        else -> return false
    }

    if (t.uncomp > 0 && body.size.toLong() != t.uncomp) return false
    val crc = CRC32()
    crc.update(body)
    return crc.value == t.crc32
}

private fun inflateRaw(data: ByteArray, uncomp: Long): ByteArray {
    val inflater = Inflater(true)
    inflater.setInput(data)
    val out = ByteArrayOutputStream(if (uncomp > 0) uncomp.toInt().coerceAtLeast(64) else 4096)
    val buf = ByteArray(8192)
    try {
        while (!inflater.finished()) {
            val n = inflater.inflate(buf)
            if (n == 0) {
                if (inflater.needsInput()) break
                if (inflater.needsDictionary()) throw ZipCrackException("dict")
            } else {
                out.write(buf, 0, n)
                if (uncomp > 0 && out.size() > uncomp + 64) break
            }
        }
    } finally {
        inflater.end()
    }
    return out.toByteArray()
}
