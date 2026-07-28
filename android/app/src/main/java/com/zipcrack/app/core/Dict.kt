package com.zipcrack.app.core

object Charsets {
    const val DIGITS = "0123456789"
    const val LATIN_LOWER = "abcdefghijklmnopqrstuvwxyz"
    const val LATIN_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    const val SYMBOLS = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`"

    const val WARN_COMBINATIONS = 2_000_000L
    const val MAX_COMBINATIONS = 50_000_000L
}

data class Dict(
    var useDigits: Boolean = true,
    var useLatinLower: Boolean = false,
    var useLatinUpper: Boolean = false,
    var useSymbols: Boolean = false,
    var minLen: Int = 1,
    var maxLen: Int = 4,
) {
    fun charset(): String = buildString {
        if (useDigits) append(Charsets.DIGITS)
        if (useLatinLower) append(Charsets.LATIN_LOWER)
        if (useLatinUpper) append(Charsets.LATIN_UPPER)
        if (useSymbols) append(Charsets.SYMBOLS)
    }

    /** null = overflow */
    fun combinationCount(): Long? {
        val n = charset().length.toLong()
        if (n == 0L || minLen <= 0 || minLen > maxLen) return 0L
        var total = 0L
        for (len in minLen..maxLen) {
            var part = 1L
            repeat(len) {
                if (part > Long.MAX_VALUE / n) return null
                part *= n
            }
            if (total > Long.MAX_VALUE - part) return null
            total += part
        }
        return total
    }
}

fun indexToPassword(idx: Long, charset: ByteArray, length: Int): String {
    val base = charset.size.toLong()
    val buf = ByteArray(length)
    var x = idx
    for (i in length - 1 downTo 0) {
        buf[i] = charset[(x % base).toInt()]
        x /= base
    }
    return String(buf, kotlin.text.Charsets.US_ASCII)
}

fun powLong(base: Long, exp: Int): Long {
    var r = 1L
    repeat(exp) { r *= base }
    return r
}
