;;
;; ASDF definition for cl-yubico
;;
;; Copyright (c) 2012 Mathias Hellevang <mathias.hellevang@gmail.com>
;; This code is licenced under LGPLv3.
;;

(defsystem #:cl-yubico
    :name "cl-yubico"
    :licence "GNU Lesser General Public Licence 3.0"
    :depends-on (:drakma :ironclad :cl-base64 :url-rewrite)
    :serial t
    :components ((:file "package")
		 (:file "cl-yubico")))
