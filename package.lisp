(defpackage #:cl-yubico
  (:documentation
   "Common Lisp Yubico client.")
  (:use #:cl)
  (:export #:initialize #:validate-otp))