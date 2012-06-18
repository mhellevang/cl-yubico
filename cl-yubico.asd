;;
;; ASDF definition for cl-yubico
;;
;; Copyright (c) 2012 Mathias Hellevang
;; This code is under the GPL.
;;

(defsystem #:cl-yubico
    :name "cl-yubico"
    :licence "GNU General Public Licence 3.0"
    :depends-on (:drakma :ironclad :cl-base64 :url-rewrite)
    :serial t
    :components ((:file "package")
		 (:file "cl-yubico")
		 ))
