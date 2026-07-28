package com.zipcrack.app.core

/**
 * How we verify passwords for the selected archive.
 */
enum class CrackBackend {
    /** In-process ZipCrypto + CRC (fast). */
    NATIVE_ZIPCRYPTO,
    /** ZIP AES (and ZipCrypto via zip4j) — pure Java. */
    JAVA_ZIP,
    /** 7z AES — Apache Commons Compress, pure Java. */
    JAVA_7Z,
    /** Encrypted OOXML/OLE Office (docx/xlsx/…) — Apache POI agile/standard. */
    JAVA_OFFICE,
}

data class ArchiveInfo(
    val displayName: String,
    /** Short label for UI, e.g. "ZIP · ZipCrypto". */
    val typeLabel: String,
    val backend: CrackBackend,
    /** True when each attempt is expensive (AES / full decrypt). */
    val slowPath: Boolean,
    val warning: String?,
    /** For NATIVE_ZIPCRYPTO */
    val zipCrypto: ZipArchive? = null,
    /** Absolute path for JAVA_* backends (temp copy of the archive). */
    val archivePath: String? = null,
)
