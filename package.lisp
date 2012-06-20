;;
;; Package for cl-yubico
;;
;; Copyright (c) 2012 Mathias Hellevang <mathias.hellevang@gmail.com>
;; This code is licenced under LGPLv3.
;;

(defpackage #:cl-yubico
  (:documentation
   "Common Lisp Yubico client.")
  (:use #:cl)
  (:export #:initialize #:validate-otp))