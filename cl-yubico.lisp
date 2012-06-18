(in-package #:cl-yubico)

(defparameter *id* nil)
(defparameter *key* nil)

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

(defun hmac-sha1-signature (key params)
  (let ((hmac (ironclad:make-hmac (base64:base64-string-to-usb8-array key)
				  :sha1))
        (unsigned (format nil  "~{~A~^&~}"
			  (loop for x in (sort (copy-list params)
					       #'string<
					       :key #'car)
			     collect (format nil "~A=~A" (car x) (cdr x))))))
    ;(break "unsigned = ~A" unsigned)
    (ironclad:update-hmac hmac (sb-ext:string-to-octets unsigned :external-format :latin1))
    (base64:usb8-array-to-base64-string
     (ironclad:hmac-digest hmac))))

(defun start-pos (expr target)
  (+ (length expr)
     (search expr target)))

(defun end-pos (target start-pos)
  (position #\Return target :start start-pos))

(defun subseq-value (expr target)
  (let* ((start-pos (start-pos expr target))
	 (end-pos (end-pos target start-pos)))
    (subseq target start-pos end-pos)))

(defun validate-otp (otp)
  (let* ((nonce (make-nonce))
	 (response (drakma:http-request
		    (format nil
			    "http://api2.yubico.com/wsapi/2.0/verify?id=~A&otp=~A&nonce=~A&h=~A"
			    *id* otp nonce (url-rewrite:url-encode
					    (hmac-sha1-signature  *key* `(("id" . ,*id*)
									  ("otp" . ,otp)
									  ("nonce" . ,nonce)))))))
	 (h-res (subseq-value "h=" response))
	 (t-res (subseq-value "t=" response))
	 (otp-res (subseq-value "otp=" response))
	 (nonce-res (subseq-value "nonce=" response))
	 (status-res (subseq-value "status=" response)))
    (format t "~%response = ~&**~&~A~&**" response)
    (format t "~%h-res = ~A" h-res)
    (format t "~%h = ~A" (hmac-sha1-signature *key* `(("id" . ,*id*)
						      ("otp" . ,otp)
						      ("nonce" . ,nonce))))
    (values (and (string= nonce nonce-res)
		 (string= otp otp-res)
		 (string= status-res "OK"))
	    status-res)
    ))

; (cl-yubico::validate-otp "cccccccvrfcbnhgfdgucbjrlidvkdvnnkbljeruducvh")
