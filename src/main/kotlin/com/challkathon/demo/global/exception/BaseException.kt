package com.challkathon.demo.global.exception

import com.challkathon.demo.global.exception.code.BaseCode
import com.challkathon.demo.global.exception.code.BaseCodeInterface

class BaseException(
    private val errorCode: BaseCodeInterface
) : RuntimeException() {

    fun getErrorCode(): BaseCode {
        return errorCode.getCode()
    }
}