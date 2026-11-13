package de.eudiwallet.backend.mdvm

const val RASP_KEY_ID = "mdvm.rasp.key_id"
const val RASP_STATUS = "mdvm.rasp.status"

abstract class RaspException(
    explanation: String,
) : MdvmException(explanation) {
    class UnknownKey(
        private val keyId: String,
    ) : RaspException("Unknown RASP key id") {
        override val internalErrorCode = InternalErrorCode.RASP_UNKNOWN_KEY

        override fun diagnosticDetails() = mapOf(MDVM_ERROR_KEY to "UnknownKey", RASP_KEY_ID to keyId)
    }

    class InvalidResponse : RaspException("RASP response cannot be parsed") {
        override val internalErrorCode = InternalErrorCode.RASP_RESPONSE_INVALID

        override fun diagnosticDetails() = mapOf(MDVM_ERROR_KEY to "InvalidRaspResponse")
    }

    class UnacceptedResponse(
        private val status: String,
        private val diagnostic: Map<String, String>,
    ) : RaspException("RASP response verification failed") {
        override val internalErrorCode = InternalErrorCode.RASP_RESPONSE_INVALID

        override fun diagnosticDetails() =
            mapOf(
                MDVM_ERROR_KEY to "UnacceptedRaspResponse",
                RASP_STATUS to status,
            ) + diagnostic.mapKeys { "mdvm.rasp.${it.key}" }
    }

    class WrongSalt : RaspException("RASP response salt is wrong") {
        override val internalErrorCode = InternalErrorCode.RASP_RESPONSE_INVALID

        override fun diagnosticDetails() = mapOf(MDVM_ERROR_KEY to "WrongRaspSalt")
    }
}
