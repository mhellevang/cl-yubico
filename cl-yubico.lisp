(defpackage #:cl-yubico
  (:documentation
   "Common Lisp Yubico client.")
  (:use #:cl))

(in-package #:cl-yubico)

(ql:quickload "drakma")
(ql:quickload "ironclad")
(ql:quickload "cl-ppcre")
(ql:quickload "cl-base64")

(defun make-salt ()
  (with-output-to-string (salt)
    (loop for x from 0 upto 40 do
	 (format salt "~A" (string (code-char (+ 32 (random 94))))))))

(defun hash-salt (salt)
  (ironclad:byte-array-to-hex-string 
   (ironclad:digest-sequence 
    :md5
    (ironclad:ascii-string-to-byte-array salt))))

(defun hmac-sha1-signature (id otp nonce)
  (break "~A ~A ~A" id otp nonce)
  (let ((unsigned (format nil "id=~A&nonce=~A&otp=~A" id nonce otp)))
    (break "unsigned= ~A" unsigned)
     (ironclad:byte-array-to-hex-string 
      (ironclad:hmac-digest (ironclad:make-hmac (ironclad:ascii-string-to-byte-array  
						 (format nil "~A" id)) 
						:sha1)
			    :buffer (ironclad:ascii-string-to-byte-array unsigned)))))

(defun validate-otp (id otp &optional salt)
  (let* ((nonce (if salt salt (hash-salt (make-salt))))
	(h (hmac-sha1-signature id otp nonce)))
    (multiple-value-bind (response http-status-code) 
	(drakma:http-request
	 (format nil
		 "http://api2.yubico.com/wsapi/2.0/verify?id=~A&otp=~A&nonce=~A"
		 id otp nonce))
      (assert (eql http-status-code 200)
	      (http-status-code)
	      "HTTP status code is ~A, should be 200" http-status-code)
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
	   (string= status-res "OK")
	   )
      h
      ))))

