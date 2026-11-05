package de.eudiwallet.backend.mdvm

abstract class RaspException(
    explanation: String,
) : MdvmException(explanation) {
    class UnknownKey(
        private val keyId: String,
    ) : RaspException("Unknown RASP key id") {
        override val internalErrorCode = InternalErrorCode.RASP_UNKNOWN_KEY

        override fun diagnosticDetails() = mapOf(MDVM_ERROR_KEY to "UnknownKey", "mdvm.rasp_key_id" to keyId)
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
                "mdvm.rasp.status" to status,
            ) + diagnostic.mapKeys { "mdvm.rasp.${it.key}" }
    }

    class WrongSalt : RaspException("RASP response salt is wrong") {
        override val internalErrorCode = InternalErrorCode.RASP_RESPONSE_INVALID

        override fun diagnosticDetails() = mapOf(MDVM_ERROR_KEY to "WrongRaspSalt")
    }
}
