;
; SymCrypt_magic.inc
; Copyright (c) Microsoft Corporation. Licensed under the MIT license.
;
; Include file to define the support macros for the Magic field
;
        extern  @SymCryptFatal@4:near


SYMCRYPT_MAGIC_FIELD    MACRO


        
                        ENDM

SYMCRYPT_CODE_VERSION   EQU     ((SYMCRYPT_CODE_VERSION_RELEASE SHL 16) OR SYMCRYPT_CODE_VERSION_PRIVATE )
SYMCRYPT_MAGIC_CONSTANT EQU     ('S1mv' + SYMCRYPT_CODE_VERSION)

SYMCRYPT_CHECK_MAGIC    MACRO   ptr, struct_name

       

        ENDM



