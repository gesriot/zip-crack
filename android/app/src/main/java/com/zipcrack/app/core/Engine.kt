package com.zipcrack.app.core

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

data class CrackResult(
    val password: String?,
    val found: Boolean,
    val cancelled: Boolean,
    val tried: Long,
    val elapsedMs: Long,
)

/** Unified password test. */
interface PasswordTester {
    fun test(password: String): Boolean
    fun cancel() {}
}

class NativeZipTester(private val archive: ZipArchive) : PasswordTester {
    override fun test(password: String): Boolean = archive.testPassword(password)
}

class CrackJob(
    private val tester: PasswordTester,
    private val dict: Dict,
    private val workers: Int,
) {
    private val cancelRequested = AtomicBoolean(false)
    private val stopWorkers = AtomicBoolean(false)
    private val tried = AtomicLong(0)
    private val found = AtomicReference<String?>(null)

    fun cancel() {
        cancelRequested.set(true)
        stopWorkers.set(true)
        tester.cancel()
    }

    fun tried(): Long = tried.get()

    fun run(onProgress: ((Long) -> Unit)? = null): CrackResult {
        val start = System.nanoTime()
        val cs = dict.charset()
        require(cs.isNotEmpty()) { "пустой алфавит" }
        require(dict.minLen > 0 && dict.minLen <= dict.maxLen) { "некорректная длина" }
        val total = dict.combinationCount()
            ?: throw IllegalArgumentException("слишком много комбинаций")
        require(total > 0) { "нет комбинаций" }
        require(total <= Charsets.MAX_COMBINATIONS) {
            "слишком много комбинаций ($total), лимит ${Charsets.MAX_COMBINATIONS}"
        }

        val charset = cs.toByteArray(kotlin.text.Charsets.US_ASCII)
        val progressThread = if (onProgress != null) {
            thread(name = "zipcrack-progress", isDaemon = true) {
                while (!stopWorkers.get() && found.get() == null) {
                    onProgress(tried.get())
                    try {
                        Thread.sleep(100)
                    } catch (_: InterruptedException) {
                        break
                    }
                }
                onProgress(tried.get())
            }
        } else null

        try {
            for (length in dict.minLen..dict.maxLen) {
                if (stopWorkers.get() || found.get() != null) break
                val span = powLong(charset.size.toLong(), length)
                val next = AtomicLong(0)
                val threads = List(workers) {
                    thread(name = "zipcrack-w$it") {
                        while (!stopWorkers.get() && found.get() == null) {
                            val i = next.getAndIncrement()
                            if (i >= span) return@thread
                            val pwd = indexToPassword(i, charset, length)
                            if (tester.test(pwd)) {
                                if (found.compareAndSet(null, pwd)) {
                                    stopWorkers.set(true)
                                    tester.cancel()
                                }
                                tried.incrementAndGet()
                                return@thread
                            }
                            tried.incrementAndGet()
                        }
                    }
                }
                threads.forEach { it.join() }
            }
        } finally {
            stopWorkers.set(true)
            progressThread?.join(500)
        }

        val elapsedMs = (System.nanoTime() - start) / 1_000_000
        val pwd = found.get()
        return CrackResult(
            password = pwd,
            found = pwd != null,
            cancelled = cancelRequested.get() && pwd == null,
            tried = tried.get(),
            elapsedMs = elapsedMs,
        )
    }

    companion object {
        fun workersFor(backend: CrackBackend): Int {
            val n = Runtime.getRuntime().availableProcessors()
            return when (backend) {
                // CPU-bound pure Java AES/LZMA/Office — use cores.
                CrackBackend.JAVA_ZIP, CrackBackend.JAVA_7Z, CrackBackend.JAVA_OFFICE ->
                    n.coerceAtLeast(2)
                CrackBackend.NATIVE_ZIPCRYPTO -> (n * 2).coerceAtLeast(4)
            }
        }
    }
}
