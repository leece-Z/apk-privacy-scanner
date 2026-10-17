package com.codebuddy.apkprivacyscanner.scanner

import android.content.Context
import android.net.Uri
import com.codebuddy.apkprivacyscanner.model.DexStringSummary
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.zip.ZipInputStream

class DexStringExtractor(private val context: Context? = null) {
    fun extract(uri: Uri): DexStringSummary {
        val appContext = requireNotNull(context) { "Context is required when extracting from Uri" }
        val inputStream = appContext.contentResolver.openInputStream(uri)
            ?: error("无法打开用户选择的 APK 文件")

        inputStream.use { rawStream ->
            ZipInputStream(rawStream.buffered()).use { zipStream ->
                val accumulator = createAccumulator()
                while (true) {
                    val entry = zipStream.nextEntry ?: break
                    val name = entry.name

                    if (name.matches(DEX_FILE_REGEX)) {
                        consumeDexEntry(
                            dexFileName = name,
                            inputStream = zipStream,
                            accumulator = accumulator
                        )
                    }

                    zipStream.closeEntry()
                }
                return buildSummary(accumulator)
            }
        }
    }

    fun createAccumulator(): DexStringAccumulator = DexStringAccumulator()

    fun consumeDexEntry(
        dexFileName: String,
        inputStream: InputStream,
        accumulator: DexStringAccumulator
    ) {
        accumulator.dexFilesScanned += dexFileName
        accumulator.totalStrings += extractEntryStrings(
            inputStream = inputStream,
            accumulator = accumulator
        )
    }

    fun buildSummary(accumulator: DexStringAccumulator): DexStringSummary {
        return DexStringSummary(
            dexFilesScanned = accumulator.dexFilesScanned,
            totalStrings = accumulator.totalStrings,
            stringSamples = accumulator.stringSamples.toList(),
            urlLikeSamples = accumulator.urlLikeSamples.toList(),
            apiLikeSamples = accumulator.apiLikeSamples.toList(),
            packageLikeSamples = accumulator.packageLikeSamples.toList()
        )
    }

    private fun extractEntryStrings(
        inputStream: InputStream,
        accumulator: DexStringAccumulator
    ): Int {
        val buffer = ByteArray(BUFFER_SIZE)
        val current = ByteArrayOutputStream()
        var totalStrings = 0

        while (true) {
            val read = inputStream.read(buffer)
            if (read == -1) {
                break
            }

            for (index in 0 until read) {
                val value = buffer[index].toInt() and 0xFF
                if (isTextCandidateByte(value)) {
                    current.write(value)
                    if (current.size() >= MAX_RAW_SEGMENT_LENGTH) {
                        totalStrings += flushString(current, accumulator)
                    }
                } else {
                    totalStrings += flushString(current, accumulator)
                }
            }
        }

        totalStrings += flushString(current, accumulator)
        return totalStrings
    }

    private fun flushString(
        current: ByteArrayOutputStream,
        accumulator: DexStringAccumulator
    ): Int {
        if (current.size() < MIN_STRING_LENGTH) {
            current.reset()
            return 0
        }

        val value = decodeUtf8OrNull(current.toByteArray())
            ?.takeIf { isReadableText(it) }
        current.reset()

        if (value == null) {
            return 0
        }

        addSample(accumulator.stringSamples, value, MAX_GENERAL_SAMPLES)

        if (URL_REGEX.containsMatchIn(value)) {
            addSample(accumulator.urlLikeSamples, value, MAX_CATEGORY_SAMPLES)
        }

        if (SENSITIVE_API_HINTS.any { value.contains(it, ignoreCase = true) }) {
            addSample(accumulator.apiLikeSamples, value, MAX_CATEGORY_SAMPLES)
        }

        val packageCandidate = value
            .trim('L', ';')
            .replace('/', '.')
        if (PACKAGE_REGEX.containsMatchIn(packageCandidate)) {
            addSample(accumulator.packageLikeSamples, packageCandidate, MAX_CATEGORY_SAMPLES)
        }

        return 1
    }

    private fun decodeUtf8OrNull(bytes: ByteArray): String? {
        return runCatching {
            val decoder = StandardCharsets.UTF_8
                .newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
            decoder.decode(ByteBuffer.wrap(bytes)).toString()
        }.getOrNull()
    }

    private fun isReadableText(value: String): Boolean {
        if (value.length < MIN_STRING_LENGTH) {
            return false
        }
        return value.any { !it.isISOControl() } &&
            value.count { it.isLetterOrDigit() || it in READABLE_SYMBOLS } >= MIN_STRING_LENGTH
    }

    private fun isTextCandidateByte(value: Int): Boolean {
        return value in PRINTABLE_ASCII_RANGE || value >= UTF8_NON_ASCII_START
    }

    private fun addSample(
        target: MutableSet<String>,
        value: String,
        limit: Int
    ) {
        if (target.size >= limit) {
            return
        }

        val sample = value.take(MAX_SAMPLE_LENGTH)
        if (sample.isNotBlank()) {
            target += sample
        }
    }

    class DexStringAccumulator {
        val dexFilesScanned = mutableListOf<String>()
        val stringSamples = linkedSetOf<String>()
        val urlLikeSamples = linkedSetOf<String>()
        val apiLikeSamples = linkedSetOf<String>()
        val packageLikeSamples = linkedSetOf<String>()
        var totalStrings = 0
    }

    private companion object {
        const val BUFFER_SIZE = 32 * 1024
        const val MIN_STRING_LENGTH = 4
        const val MAX_SAMPLE_LENGTH = 160
        const val MAX_GENERAL_SAMPLES = 80
        const val MAX_CATEGORY_SAMPLES = 20
        const val MAX_RAW_SEGMENT_LENGTH = 4096
        const val UTF8_NON_ASCII_START = 0x80
        val PRINTABLE_ASCII_RANGE = 0x20..0x7E
        val READABLE_SYMBOLS = setOf('.', '/', '_', '-', ':', '$', ';', '(', ')')
        val DEX_FILE_REGEX = Regex("classes(\\d*)\\.dex")
        val URL_REGEX = Regex("https?://[A-Za-z0-9._~:/?#\\[\\]@!$&'()*+,;=%-]+")
        val PACKAGE_REGEX = Regex("([A-Za-z_][A-Za-z0-9_]*\\.){2,}[A-Za-z_][A-Za-z0-9_]*")
        val SENSITIVE_API_HINTS = listOf(
            "getDeviceId",
            "getSubscriberId",
            "getLine1Number",
            "getSimSerialNumber",
            "getMacAddress",
            "getSSID",
            "getBSSID",
            "getInstalledPackages",
            "getAccounts",
            "getLastKnownLocation",
            "requestLocationUpdates",
            "TelephonyManager",
            "WifiManager"
        )
    }
}
