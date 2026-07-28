package com.zipcrack.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Bundle
import android.text.InputType
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.zipcrack.app.core.ArchiveInfo
import com.zipcrack.app.core.ArchiveProbe
import com.zipcrack.app.core.Charsets
import com.zipcrack.app.core.CrackBackend
import com.zipcrack.app.core.CrackJob
import com.zipcrack.app.core.Dict
import com.zipcrack.app.core.NativeZipTester
import com.zipcrack.app.core.OfficePasswordTester
import com.zipcrack.app.core.SevenZPasswordTester
import com.zipcrack.app.core.Zip4jPasswordTester
import com.zipcrack.app.core.ZipCrackException
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicReference

class MainActivity : AppCompatActivity() {

    private val dict = Dict()
    /** Stable copy under filesDir (survives cache wipes / re-probe). */
    private var archiveFile: File? = null
    private var archiveInfo: ArchiveInfo? = null
    private var archiveName: String = "Файл не выбран"
    private var lastProbeError: String? = null
    private var running = false
    private val jobRef = AtomicReference<CrackJob?>(null)
    private val executor = Executors.newSingleThreadExecutor()

    private lateinit var pathLabel: TextView
    private lateinit var typeLabel: TextView
    private lateinit var warnLabel: TextView
    private lateinit var statusLabel: TextView
    private lateinit var passwordLabel: TextView
    private lateinit var statsLabel: TextView
    private lateinit var charsetPreview: TextView
    private lateinit var combosLabel: TextView
    private lateinit var progress: ProgressBar
    private lateinit var btnCrack: Button
    private lateinit var btnCancel: Button
    private lateinit var btnPick: Button
    private lateinit var btnCopy: Button
    private lateinit var cbDigits: CheckBox
    private lateinit var cbLower: CheckBox
    private lateinit var cbUpper: CheckBox
    private lateinit var cbSymbols: CheckBox
    private lateinit var minLenEdit: EditText
    private lateinit var maxLenEdit: EditText

    private val pickFile = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri == null) return@registerForActivityResult
        try {
            // Persist permission when possible (SAF may revoke after callback on some OEMs).
            try {
                val flags = Intent.FLAG_GRANT_READ_URI_PERMISSION
                contentResolver.takePersistableUriPermission(uri, flags)
            } catch (_: Exception) {
                // not persistable — we copy bytes immediately below
            }

            archiveName = uri.lastPathSegment?.substringAfterLast(':')
                ?.substringAfterLast('/')
                ?: uri.toString()
            pathLabel.text = archiveName
            statusLabel.text = "Чтение файла…"
            statusLabel.setTextColor(C.MUTED)
            passwordLabel.visibility = View.GONE
            btnCopy.visibility = View.GONE
            statsLabel.text = ""

            val dest = File(filesDir, "selected_archive.bin")
            contentResolver.openInputStream(uri)?.use { input ->
                dest.outputStream().use { output -> input.copyTo(output) }
            } ?: throw ZipCrackException("не удалось открыть файл (openInputStream=null)")

            if (!dest.isFile || dest.length() == 0L) {
                throw ZipCrackException("файл пуст или не скопировался")
            }
            archiveFile = dest
            lastProbeError = null
            probeSelected()
        } catch (e: Exception) {
            archiveFile = null
            archiveInfo = null
            lastProbeError = e.message ?: e.toString()
            pathLabel.text = "Файл не выбран"
            typeLabel.text = ""
            warnLabel.visibility = View.GONE
            statusLabel.text = lastProbeError
            statusLabel.setTextColor(C.ERROR)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(buildUi())
        refreshCombos()
    }

    override fun onDestroy() {
        jobRef.get()?.cancel()
        executor.shutdownNow()
        super.onDestroy()
    }

    private fun probeSelected(): Boolean {
        val file = archiveFile
        if (file == null || !file.isFile || file.length() == 0L) {
            archiveInfo = null
            lastProbeError = "файл архива не загружен"
            return false
        }

        statusLabel.text = "Анализ архива…"
        statusLabel.setTextColor(C.MUTED)

        val work = File(filesDir, "archives").apply { mkdirs() }
        // Do not delete the selected_archive.bin — only probe copies.
        work.listFiles()?.forEach { child ->
            if (child.name.startsWith("input_")) child.delete()
        }

        return try {
            val bytes = file.readBytes()
            val info = ArchiveProbe.probe(bytes, archiveName, work)
            archiveInfo = info
            lastProbeError = null
            typeLabel.text = "Тип: ${info.typeLabel}" + when (info.backend) {
                CrackBackend.NATIVE_ZIPCRYPTO -> " · движок: native"
                CrackBackend.JAVA_ZIP -> " · движок: zip4j"
                CrackBackend.JAVA_7Z -> " · движок: commons-compress"
                CrackBackend.JAVA_OFFICE -> " · движок: POI"
            }
            typeLabel.setTextColor(C.TEXT)
            if (info.warning != null) {
                warnLabel.visibility = View.VISIBLE
                warnLabel.text = info.warning
                warnLabel.setTextColor(C.WARN)
            } else {
                warnLabel.visibility = View.GONE
            }
            statusLabel.text = "Архив выбран (${file.length()} байт). Нажмите «Подобрать»."
            statusLabel.setTextColor(C.TEXT)
            refreshCombos()
            true
        } catch (e: Exception) {
            archiveInfo = null
            lastProbeError = e.message ?: e.toString()
            typeLabel.text = ""
            warnLabel.visibility = View.GONE
            statusLabel.text = lastProbeError
            statusLabel.setTextColor(C.ERROR)
            false
        }
    }

    private fun buildUi(): View {
        val root = ScrollView(this).apply {
            setBackgroundColor(C.WINDOW)
            isFillViewport = true
        }
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(24))
        }

        col.addView(TextView(this).apply {
            text = "Password Cracker"
            setTextColor(C.TEXT)
            textSize = 20f
            typeface = Typeface.DEFAULT_BOLD
            setPadding(0, 0, 0, dp(12))
        })

        pathLabel = TextView(this).apply {
            text = archiveName
            setTextColor(C.MUTED)
            textSize = 14f
            setPadding(0, 0, 0, dp(4))
        }
        col.addView(pathLabel)

        typeLabel = TextView(this).apply {
            text = ""
            setTextColor(C.TEXT)
            textSize = 13f
            setPadding(0, 0, 0, dp(4))
        }
        col.addView(typeLabel)

        warnLabel = TextView(this).apply {
            visibility = View.GONE
            textSize = 13f
            setPadding(0, 0, 0, dp(8))
        }
        col.addView(warnLabel)

        val buttons = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
        }
        btnPick = Button(this).apply {
            text = "Выбрать файл…"
            setOnClickListener {
                if (!running) {
                    pickFile.launch(
                        arrayOf(
                            "application/zip",
                            "application/x-zip-compressed",
                            "application/x-7z-compressed",
                            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                            "application/msword",
                            "application/vnd.ms-excel",
                            "application/vnd.ms-powerpoint",
                            "application/octet-stream",
                            "*/*",
                        )
                    )
                }
            }
        }
        btnCrack = Button(this).apply {
            text = "Подобрать"
            setOnClickListener { startCrack() }
        }
        btnCancel = Button(this).apply {
            text = "Отмена"
            isEnabled = false
            setOnClickListener { cancelCrack() }
        }
        buttons.addView(btnPick, lp(0, wrap, 1f))
        buttons.addView(View(this), lp(dp(8), 1))
        buttons.addView(btnCrack, lp(0, wrap, 1f))
        buttons.addView(View(this), lp(dp(8), 1))
        buttons.addView(btnCancel, lp(0, wrap, 1f))
        col.addView(buttons)
        col.addView(space(12))

        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = rounded(C.CARD, C.BORDER)
            setPadding(dp(12), dp(10), dp(12), dp(12))
        }
        card.addView(TextView(this).apply {
            text = "Словарь (алфавит)"
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(C.TEXT)
            textSize = 14f
            setPadding(0, 0, 0, dp(8))
        })

        cbDigits = check("Цифры 0–9", dict.useDigits) { dict.useDigits = it; refreshCombos() }
        cbLower = check("Латиница a–z", dict.useLatinLower) { dict.useLatinLower = it; refreshCombos() }
        cbUpper = check("Латиница A–Z", dict.useLatinUpper) { dict.useLatinUpper = it; refreshCombos() }
        cbSymbols = check("Прочие символы  !@#\$…", dict.useSymbols) { dict.useSymbols = it; refreshCombos() }
        card.addView(cbDigits)
        card.addView(cbLower)
        card.addView(cbUpper)
        card.addView(cbSymbols)
        card.addView(space(6))

        val lenRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        lenRow.addView(TextView(this).apply {
            text = "Длина от"
            setTextColor(C.TEXT)
            textSize = 14f
        })
        minLenEdit = numEdit(dict.minLen) {
            dict.minLen = it
            if (dict.minLen > dict.maxLen) {
                dict.maxLen = dict.minLen
                maxLenEdit.setText(dict.maxLen.toString())
            }
            refreshCombos()
        }
        maxLenEdit = numEdit(dict.maxLen) {
            dict.maxLen = it
            if (dict.minLen > dict.maxLen) {
                dict.minLen = dict.maxLen
                minLenEdit.setText(dict.minLen.toString())
            }
            refreshCombos()
        }
        lenRow.addView(minLenEdit, lp(dp(64), wrap).also { it.leftMargin = dp(8); it.rightMargin = dp(8) })
        lenRow.addView(TextView(this).apply {
            text = "до"
            setTextColor(C.TEXT)
            textSize = 14f
        })
        lenRow.addView(maxLenEdit, lp(dp(64), wrap).also { it.leftMargin = dp(8) })
        card.addView(lenRow)
        card.addView(space(8))

        charsetPreview = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            textSize = 12f
            setTextColor(C.MUTED)
        }
        card.addView(HorizontalScrollView(this).apply {
            addView(charsetPreview)
            isHorizontalScrollBarEnabled = false
        })
        combosLabel = TextView(this).apply {
            textSize = 13f
            setTextColor(C.TEXT)
            setPadding(0, dp(6), 0, 0)
        }
        card.addView(combosLabel)
        col.addView(card)
        col.addView(space(12))

        progress = ProgressBar(this).apply {
            isIndeterminate = true
            visibility = View.GONE
        }
        col.addView(progress, lp(match, wrap).also { it.gravity = Gravity.CENTER_HORIZONTAL })

        statusLabel = TextView(this).apply {
            text = "Выберите архив и настройте словарь"
            setTextColor(C.TEXT)
            textSize = 14f
            setPadding(0, dp(8), 0, 0)
        }
        col.addView(statusLabel)

        passwordLabel = TextView(this).apply {
            visibility = View.GONE
            typeface = Typeface.MONOSPACE
            textSize = 18f
            setTextColor(C.TEXT)
            setPadding(0, dp(10), 0, 0)
        }
        col.addView(passwordLabel)

        btnCopy = Button(this).apply {
            text = "Копировать пароль"
            visibility = View.GONE
            setOnClickListener {
                val pwd = passwordLabel.tag as? String ?: return@setOnClickListener
                val cm = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(ClipData.newPlainText("password", pwd))
                Toast.makeText(this@MainActivity, "Скопировано", Toast.LENGTH_SHORT).show()
            }
        }
        col.addView(btnCopy)

        statsLabel = TextView(this).apply {
            setTextColor(C.MUTED)
            textSize = 13f
            setPadding(0, dp(6), 0, 0)
        }
        col.addView(statsLabel)

        col.addView(space(16))
        col.addView(TextView(this).apply {
            text = "Автовыбор: ZIP ZipCrypto → native; ZIP AES → zip4j; 7z → Commons Compress; " +
                "encrypted DOCX/XLSX → Apache POI (Word на планшете не нужен)."
            setTextColor(C.MUTED)
            textSize = 12f
        })

        root.addView(col)
        return root
    }

    private fun startCrack() {
        if (running) return

        // Re-probe if needed (activity recreation, failed first probe, wiped cache copies).
        if (archiveInfo == null) {
            if (archiveFile != null) {
                if (!probeSelected()) {
                    statusLabel.text = lastProbeError
                        ?: "Не удалось разобрать архив"
                    statusLabel.setTextColor(C.ERROR)
                    return
                }
            } else {
                statusLabel.text = lastProbeError
                    ?: "Сначала выберите архив (кнопка «Выбрать файл…»)"
                statusLabel.setTextColor(C.ERROR)
                return
            }
        }

        val info = archiveInfo
        if (info == null) {
            statusLabel.text = lastProbeError ?: "Архив не готов — выберите файл ещё раз"
            statusLabel.setTextColor(C.ERROR)
            return
        }

        // Ensure on-disk path still exists for Java backends.
        if (info.backend != CrackBackend.NATIVE_ZIPCRYPTO) {
            val p = info.archivePath
            if (p == null || !File(p).isFile) {
                if (!probeSelected()) {
                    statusLabel.text = lastProbeError ?: "потерян временный файл архива"
                    statusLabel.setTextColor(C.ERROR)
                    return
                }
            }
        }
        val ready = archiveInfo ?: run {
            statusLabel.text = "Архив не готов"
            statusLabel.setTextColor(C.ERROR)
            return
        }

        syncDictFromUi()
        val combos = dict.combinationCount()
        if (dict.charset().isEmpty()) {
            statusLabel.text = "Выберите хотя бы один набор символов"
            statusLabel.setTextColor(C.ERROR)
            return
        }
        if (combos == null || combos <= 0) {
            statusLabel.text = "Нет комбинаций для перебора"
            statusLabel.setTextColor(C.ERROR)
            return
        }
        if (combos > Charsets.MAX_COMBINATIONS) {
            statusLabel.text =
                "Слишком много комбинаций ($combos). Уменьшите длину или алфавит (лимит ${Charsets.MAX_COMBINATIONS})."
            statusLabel.setTextColor(C.ERROR)
            return
        }

        val tester = try {
            when (ready.backend) {
                CrackBackend.NATIVE_ZIPCRYPTO -> {
                    val z = ready.zipCrypto ?: throw ZipCrackException("нет ZipCrypto-данных")
                    NativeZipTester(z)
                }
                CrackBackend.JAVA_ZIP -> {
                    val path = ready.archivePath ?: throw ZipCrackException("нет пути к архиву")
                    Zip4jPasswordTester(File(path))
                }
                CrackBackend.JAVA_7Z -> {
                    val path = ready.archivePath ?: throw ZipCrackException("нет пути к архиву")
                    SevenZPasswordTester(File(path))
                }
                CrackBackend.JAVA_OFFICE -> {
                    val path = ready.archivePath ?: throw ZipCrackException("нет пути к архиву")
                    OfficePasswordTester(File(path))
                }
            }
        } catch (e: Exception) {
            statusLabel.text = e.message ?: e.toString()
            statusLabel.setTextColor(C.ERROR)
            return
        }

        running = true
        setControlsEnabled(false)
        btnCancel.isEnabled = true
        progress.visibility = View.VISIBLE
        passwordLabel.visibility = View.GONE
        btnCopy.visibility = View.GONE
        statsLabel.text = ""
        statusLabel.setTextColor(C.TEXT)
        statusLabel.text = "Идёт подбор…"

        val snapshot = dict.copy()
        val workers = CrackJob.workersFor(ready.backend)
        val job = CrackJob(tester, snapshot, workers)
        jobRef.set(job)

        executor.execute {
            val result = try {
                job.run { tried ->
                    runOnUiThread {
                        if (running) {
                            statusLabel.text = "Идёт подбор… проверено $tried"
                        }
                    }
                }
            } catch (e: Exception) {
                runOnUiThread {
                    finishRun()
                    statusLabel.text = e.message ?: e.toString()
                    statusLabel.setTextColor(C.ERROR)
                }
                return@execute
            }

            runOnUiThread {
                finishRun()
                when {
                    result.found && result.password != null -> {
                        statusLabel.text = "Пароль найден: ${result.password}"
                        statusLabel.setTextColor(0xFF1B7F3A.toInt())
                        passwordLabel.visibility = View.VISIBLE
                        passwordLabel.text = "Пароль: ${result.password}"
                        passwordLabel.tag = result.password
                        btnCopy.visibility = View.VISIBLE
                    }
                    result.cancelled -> {
                        statusLabel.text = "Отменено (проверено ${result.tried} вариантов)"
                        statusLabel.setTextColor(C.WARN)
                    }
                    else -> {
                        statusLabel.text = "Пароль не найден (проверено ${result.tried} вариантов)"
                        statusLabel.setTextColor(C.TEXT)
                    }
                }
                val secs = result.elapsedMs / 1000.0
                statsLabel.text = "Время: ${"%.3f".format(secs)} с · проверено: ${result.tried}" +
                    " · воркеров: $workers"
            }
        }
    }

    private fun cancelCrack() {
        if (!running) return
        statusLabel.text = "Отмена…"
        statusLabel.setTextColor(C.WARN)
        jobRef.get()?.cancel()
        btnCancel.isEnabled = false
    }

    private fun finishRun() {
        running = false
        jobRef.set(null)
        progress.visibility = View.GONE
        btnCancel.isEnabled = false
        setControlsEnabled(true)
    }

    private fun setControlsEnabled(enabled: Boolean) {
        btnPick.isEnabled = enabled
        btnCrack.isEnabled = enabled
        cbDigits.isEnabled = enabled
        cbLower.isEnabled = enabled
        cbUpper.isEnabled = enabled
        cbSymbols.isEnabled = enabled
        minLenEdit.isEnabled = enabled
        maxLenEdit.isEnabled = enabled
    }

    private fun syncDictFromUi() {
        dict.useDigits = cbDigits.isChecked
        dict.useLatinLower = cbLower.isChecked
        dict.useLatinUpper = cbUpper.isChecked
        dict.useSymbols = cbSymbols.isChecked
        dict.minLen = minLenEdit.text.toString().toIntOrNull()?.coerceIn(1, 64) ?: 1
        dict.maxLen = maxLenEdit.text.toString().toIntOrNull()?.coerceIn(1, 64) ?: 4
        if (dict.minLen > dict.maxLen) dict.maxLen = dict.minLen
    }

    private fun refreshCombos() {
        if (!::combosLabel.isInitialized) return
        syncDictFromUi()
        val cs = dict.charset()
        charsetPreview.text = if (cs.isEmpty()) {
            "(алфавит пуст)"
        } else {
            "Символов: ${cs.length}  ·  $cs"
        }
        when (val n = dict.combinationCount()) {
            null -> {
                combosLabel.text = "Комбинаций: слишком много (переполнение)"
                combosLabel.setTextColor(C.ERROR)
            }
            0L -> {
                combosLabel.text = "Комбинаций: 0"
                combosLabel.setTextColor(C.ERROR)
            }
            else -> {
                val slow = archiveInfo?.slowPath == true
                combosLabel.text = when {
                    n > Charsets.MAX_COMBINATIONS ->
                        "Комбинаций: $n — слишком много (лимит ${Charsets.MAX_COMBINATIONS})"
                    n > Charsets.WARN_COMBINATIONS ->
                        "Комбинаций: $n — может занять много времени"
                    slow && n > 10_000 ->
                        "Комбинаций: $n — AES/7z может занять заметное время"
                    else -> "Комбинаций: $n"
                }
                combosLabel.setTextColor(
                    when {
                        n > Charsets.MAX_COMBINATIONS -> C.ERROR
                        n > Charsets.WARN_COMBINATIONS || (slow && n > 10_000) -> C.WARN
                        else -> C.TEXT
                    }
                )
            }
        }
    }

    private fun check(label: String, checked: Boolean, on: (Boolean) -> Unit): CheckBox =
        CheckBox(this).apply {
            text = label
            isChecked = checked
            setTextColor(C.TEXT)
            setOnCheckedChangeListener { _, v -> on(v) }
        }

    private fun numEdit(value: Int, onChange: (Int) -> Unit): EditText =
        EditText(this).apply {
            setText(value.toString())
            inputType = InputType.TYPE_CLASS_NUMBER
            textSize = 14f
            setTextColor(C.TEXT)
            background = rounded(C.FIELD, C.BORDER, 4f)
            setPadding(dp(8), dp(6), dp(8), dp(6))
            setOnFocusChangeListener { _, has ->
                if (!has) {
                    val v = text.toString().toIntOrNull()?.coerceIn(1, 64) ?: value
                    setText(v.toString())
                    onChange(v)
                }
            }
        }

    private fun space(h: Int) = View(this).apply {
        layoutParams = LinearLayout.LayoutParams(match, dp(h))
    }

    private fun dp(v: Int): Int =
        TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v.toFloat(), resources.displayMetrics).toInt()

    private fun rounded(fill: Int, stroke: Int, radiusDp: Float = 8f) =
        GradientDrawable().apply {
            setColor(fill)
            setStroke(1, stroke)
            cornerRadius = radiusDp * resources.displayMetrics.density
        }

    private fun lp(w: Int, h: Int, weight: Float = 0f) =
        LinearLayout.LayoutParams(w, h, weight)

    companion object {
        private val match = LinearLayout.LayoutParams.MATCH_PARENT
        private val wrap = LinearLayout.LayoutParams.WRAP_CONTENT
    }

    private object C {
        const val WINDOW = 0xFFF4F5F2.toInt()
        const val CARD = 0xFFFFFFFF.toInt()
        const val FIELD = 0xFFFFFFFF.toInt()
        const val TEXT = 0xFF1F2933.toInt()
        const val MUTED = 0xFF65717C.toInt()
        const val BORDER = 0xFFCFD6DD.toInt()
        const val ERROR = 0xFFDC5050.toInt()
        const val WARN = 0xFFDC9A28.toInt()
    }
}
