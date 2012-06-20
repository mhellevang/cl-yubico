(in-package #:cl-yubico)

(defvar *id* nil)
(defvar *key* nil)

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
  ;(format t "~%params = ~S" params)
  (let ((hmac (ironclad:make-hmac (base64:base64-string-to-usb8-array key)
				  :sha1))
        (unsigned (format nil  "~{~A~^&~}"
			  (loop for x in (sort (copy-list params)
					       #'string<
					       :key #'car)
			     collect (format nil "~A=~A" (car x) (cdr x))))))
    ;(format t "~%unsigned = ~S~&" unsigned)
    (ironclad:update-hmac hmac (sb-ext:string-to-octets unsigned :external-format :latin1))
    (base64:usb8-array-to-base64-string
     (ironclad:hmac-digest hmac))))

(defun start-pos (expr target)
  (when (and expr target)
    (let ((pos (search expr target)))
      (when pos (+ (length expr) pos)))))

(defun end-pos (target start-pos)
  (when (and target start-pos)
    (position #\Return target :start start-pos)))

(defun subseq-value (expr target)
  (let* ((start-pos (start-pos expr target))
	 (end-pos (end-pos target start-pos)))
    (if (and start-pos end-pos)
	(subseq target start-pos end-pos)
	nil)))

(defun valid-otp-format (otp)
  (<= 32 (length otp) 48))

(defun validate-otp (otp)
  (assert (and *id* *key*) (*id* *key*)
	  "Client not initalized. Initialize by calling (cl-yubico:initialize) first.")
  (assert (valid-otp-format otp) (otp)
	  "Invalid otp submitted.")
  (let* ((nonce (make-nonce))
	 (response (drakma:http-request
		    (format nil
			    "http://api.yubico.com/wsapi/2.0/verify?id=~A&otp=~A&nonce=~A&h=~A"
			    *id* otp nonce (url-rewrite:url-encode
					    (hmac-sha1-signature *key* `(("id" . ,*id*)
									 ("otp" . ,otp)
									 ("nonce" . ,nonce)))))))
	 (h-res (subseq-value "h=" response))
	 (t-res (subseq-value "t=" response))
	 (otp-res (subseq-value "otp=" response))
	 (nonce-res (subseq-value "nonce=" response))
	 (sl-res (subseq-value "sl=" response))
	 (status-res (subseq-value "status=" response))
	 (timestamp-res (subseq-value "timestamp" response))
	 (sessioncounter-res (subseq-value "sessioncounter" response))
	 (sessionuse-res (subseq-value "sessionuse" response))
	 (unsigned-params ()))
    (when t-res (push `("t" . ,t-res) unsigned-params))
    (when otp-res (push `("otp" . ,otp-res) unsigned-params))
    (when nonce-res (push `("nonce" . ,nonce-res) unsigned-params))
    (when sl-res (push `("sl" . ,sl-res) unsigned-params))
    (when status-res (push `("status" . ,status-res) unsigned-params))
    (when timestamp-res (push `("timestamp" . ,timestamp-res) unsigned-params))
    (when sessioncounter-res (push `("sessioncounter" . ,sessioncounter-res) unsigned-params))
    (when sessionuse-res (push `("sessionuse" . ,sessionuse-res) unsigned-params))
    (values (and (string= nonce nonce-res)
		 (string= otp otp-res)
		 (string= h-res (hmac-sha1-signature *key* unsigned-params))
		 (string= status-res "OK"))
	    (intern (substitute #\- #\_ status-res) :keyword))))