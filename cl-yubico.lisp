(defpackage #:cl-yubico
  (:documentation
   "Common Lisp Yubico client.")
  (:use #:cl))

(in-package #:cl-yubico)

(defparameter *id* nil)
(defparameter *key* nil)

(ql:quickload "drakma")
(ql:quickload "ironclad")
(ql:quickload "cl-ppcre")
(ql:quickload "cl-base64")
;(ql:quickload "hunchentoot") ;; url encode?
(ql:quickload "url-rewrite")

(defun initialize-cl-yubico (id key)
  "Initialize the client. id is your client id, key is your secret API key."
  (check-type id integer)
  (check-type key string)
  (setf *id* id)
  (setf *key* key))

(defun make-nonce ()
  (ironclad:byte-array-to-hex-string
   (ironclad:digest-sequence
    :md5
    (ironclad:ascii-string-to-byte-array
     (with-output-to-string (salt)
       (loop for x from 0 upto 40 do
	    (format salt "~A" (string (code-char (+ 32 (random 94)))))))))))

(defun hmac-sha1-signature (id key otp nonce)
  (let ((unsigned (format nil "id=~A&nonce=~A&otp=~A" id nonce otp))
	(hmac (ironclad:make-hmac (base64:base64-string-to-usb8-array key)
					       :sha1)))
    (ironclad:update-hmac hmac (sb-ext:string-to-octets unsigned :external-format :latin1))
    (base64:usb8-array-to-base64-string
     (ironclad:hmac-digest hmac))))

(defun validate-otp (otp)
  (let* ((nonce (make-nonce))
	 (h (hmac-sha1-signature *id* *key* otp nonce)))
    (multiple-value-bind (response http-status-code)
	(drakma:http-request
	 (format nil
		 "http://api2.yubico.com/wsapi/2.0/verify?id=~A&otp=~A&nonce=~A&h=~A"
		 *id* otp nonce (url-rewrite:url-encode h)))
      ;; (assert (eql http-status-code 200)
      ;; 	      (http-status-code)
      ;; 	      "HTTP status code is ~A, should be 200" http-status-code)
      (break "response= ~A" response)
    (let* ((otp-start (+ 4 (search "otp=" response)))
	   (otp-end (position #\Return response :start otp-start))
	   (otp-res (subseq response otp-start otp-end))
	   (nonce-start (+ 6 (search "nonce=" response :start2 otp-end)))
	   (nonce-end (position #\Return response :start nonce-start))
	   (nonce-res (subseq response nonce-start nonce-end))
	   (status-start (+ 7 (search "status=" response :start2 nonce-end)))
	   (status-end (position #\Return response :start status-start))
	   (status-res (subseq response status-start status-end)))
      (and (string= nonce nonce-res)
	   (string= otp otp-res)
	   (string= status-res "OK"))
	   h
	   ))))