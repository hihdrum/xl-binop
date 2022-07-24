(defmacro with-open-binary-file ((stream filename &rest options) &body body)
  `(with-open-file (,stream ,filename :encoding :binary ,@options)
	 ,@body))

(defmacro with-input-from-binary-file ((stream filename &rest options) &body body)
  `(with-open-binary-file (,stream, filename :direction :input ,@options)
	 ,@body))

(defmacro with-output-to-binary-file ((stream filename &rest options) &body body)
  `(with-open-binary-file (,stream ,filename :direction :output ,@options)
	 ,@body))

(defun make-string-to-binary-string (str)
  (convert-encoding-to-internal *encoding-binary* str))

(defun make-string-binary-input-stream (str)
  (let ((bin-str (make-string-to-binary-string str)))
	(make-string-input-stream bin-str)))

(defun read-n-char (times &optional in eof-error-p eof-value)
  (let ((result (make-vector times :element-type 'character :fill-pointer 0)))
	(dotimes (i times result)
	  (let ((c (read-char in eof-error-p eof-value)))
		(if (eq eof-value c)
			(return result)
		  (vector-push c result))))))

(defun write-byte-list-log (bytes &optional (stream *standard-output*))
  (format-date stream "%Y%m%d%H%M%S000")
  (format stream "~10,'0D" (length bytes))
  (dolist (b bytes)
	(write-char (code-char b) stream)))

(defun write-byte-list-to-file (bytes filepath)
  (with-open-file (s filepath :direction :output :if-doex-not-exist :create :encoding :binary)
	(write-byte-list-log bytes s)))

(defun write-short-int (x &key (little t))
  (if little
	  (progn
		(write-char (code-char (ldb (byte 8 0) x)))
		(write-char (code-char (ldb (byte 8 8) x)))
		x)
	(progn
	  (write-char (code-char (ldb (byte 8 8) x)))
	  (write-char (code-char (ldb (byte 8 0) x)))
	  x)))

(defun hex-string (str)
  (let ((bin-str (convert-encoding-to-internal *encoding-binary* str)))
	(format nil "~{~2,'0x~^ ~}" (map 'list #'char-code bin-str))))

(defun hex-dump (stream)
  (let ((bin-str (convert-encoding-to-internal *encoding-binary* stream)))
	(hex-string bin-str)))

(defun %print-hex-dump (n stream)
  (let (c (counter 0))
	(loop
	  (setq c (read-char stream nil :eof))
	  (if (eq c :eof)
		  (return))
	  (incf counter)
	  (princ (format nil "~2,'0x" (char-code c)))
	  (if (= n counter)
		  (progn
			(princ #\newline)
			(setq counter 0))
		(progn
		  (princ #\SPC))))))

(defun print-hex-dump (str)
  (let (c (counter 0) (v (make-vector 16 :element-type 'character :fill-pointer 0))
		  (line-counter 0)
		  (s (make-string-input-stream str)))
	(loop
	  (setq c (read-char s nil :eof))
	  (if (eq c :eof)
		  (progn
			(unless (eq 0 counter)
			  (format t "~8,'0X: ~{~2,'0X~^ ~} : ~A~%"
					  (* line-counter 16) (map 'list #'char-code v) (map 'string #'display-char v)))
			(return)))
	  (incf counter)
	  (vector-push c v)
	  (if (= 16 counter)
		  (progn
			(format t "~8,'0X: ~{~2,'0X~^ ~} : ~A~%"
					(* line-counter 16) (map 'list #'char-code v) (map 'string #'display-char v))
			(setq counter 0)
			(incf line-counter)
			(setq v (make-vector 16 :element-type 'character :fill-pointer 0)))))))


(defun display-char (c &optional (sub-c #\.))
  (if (graphic-char-p c)
	  c
	sub-c))

(defun 4-binary-string-to-integer (bin-str)
  (let ((v (map 'vector #'char-code bin-str)))
	(+ (svref v 0)
	   (ash (svref v 1) 8)
	   (ash (svref v 2) 16)
	   (ash (svref v 3) 24))))

(defun section-header-block (&optional in)
  (format t "Section Header Block~%")
  (format t "Block Type : ~A~%" (hex-string (read-n-char 4 in)))
  (format t "Block Txotal Length : ~A~%" (hex-string (read-n-char 4 in)))
  (format t "Byte-Order-Magic : ~A~%" (hex-string (read-n-char 4 in)))
  (format t "major version : ~A~%" (hex-string (read-n-char 2)))
  (format t "minor version : ~A~%" (hex-string (read-n-char 2)))
  (format t "Section Length : ~A~%" (hex-string (read-n-char 4 in)))
  (format t "Block Total Length : ~A~%" (hex-string (read-n-char 4 in)))
  )

(defun little-endian-p (magic-str)
  (string= (map 'string #'code-char #(#x4d #x3c #x2b #x1a)) magic-str))

(defun read-section-header-block (&optional in)
  (let (result)
	(setq result (read-n-char 4 in))
	(let ((size-str (read-n-char 4)))
	  (setq result (concat result size-str))
	  (setq result (concat result (read-n-char (- (4-binary-string-to-integer size-str) 8)))))
	result))

(defstruct pcap-header
  tcpdump-magic major-version minor-version time-zone sigfigs scaplen link-type)

(defun read-pcap-header-raw (&optional in)
  (make-pcap-header
   :tcpdump-magic (read-n-char 4 in)
   :major-version (read-n-char 2 in)
   :minor-version (read-n-char 2 in)
   :time-zone (read-n-char 4 in)
   :sigfigs (read-n-char 4 in)
   :scaplen (read-n-char 4 in)
   :link-type (read-n-char 4 in)))

(defun print-pcap-header-raw (ph)
  (flet ((print-help (name data)
		   (format t "~20@A : ~{~2,'0X~^ ~}~%" name (map 'list #'char-code data))))
	(print-help "tcpdump-magic" (pcap-header-tcpdump-magic ph))
	(print-help "major-version" (pcap-header-major-version ph))
	(print-help "minor-version" (pcap-header-minor-version ph))
	(print-help "time-zone" (pcap-header-time-zone ph))
	(print-help "sigfigs" (pcap-header-sigfigs ph))
	(print-help "scaplen" (pcap-header-scaplen ph))
	(print-help "link-type" (pcap-header-link-type ph))))

(defstruct packet-header
  time-stamp caplen len)

(defun read-packet-header-raw (&optional in)
  (make-packet-header
   :time-stamp (read-n-char 8 in)
   :caplen (read-n-char 4 in)
   :len (read-n-char 4 in)))

(defun print-packet-header-raw (ph)
  (flet ((print-help (name data)
		   (format t "~20@A : ~{~2,'0X~^ ~}~%" name (map 'list #'char-code data))))
	(print-help "time-stamp" (packet-header-time-stamp ph))
	(print-help "caplen" (packet-header-caplen ph))
	(print-help "len" (packet-header-len ph))))

(defstruct ethernet2
  destination
  source
  type)

(defun read-ethernet2-raw (&optional in)
  (make-ethernet2
   :destination (read-n-char 6 in)
   :source (read-n-char 6 in)
   :type (read-n-char 2 in)))

(defun print-ethernet2-raw (eth2)
  (flet ((print-help (name data)
		   (format t "~20@A : ~{~2,'0X~^ ~}~%" name (map 'list #'char-code data))))
	(print-help "destination" (ethernet2-destination eth2))
	(print-help "caplen" (ethernet2-source eth2))
	(print-help "len" (ethernet2-type eth2))))

(defstruct ip-header
  version-ihl
  type-of-service
  total-length
  identification
  flags-fragment-offset
  time-to-live
  protocol
  header-checksum
  souce-ip-address
  destination-ip-address
  optons-padding)

(defun read-ip-header-raw (&optional in)
  (make-ip-header
   :version-ihl (read-n-char 1 in)
   :type-of-service (read-n-char 1 in)
   :total-length (read-n-char 2 in)
   :identification (read-n-char 2 in)
   :flags-fragment-offset (read-n-char 2 in)
   :time-to-live (read-n-char 1 in)
   :protocol (read-n-char 1 in)
   :header-checksum (read-n-char 2 in)
   :souce-ip-address (read-n-char 4 in)
   :destination-ip-address (read-n-char 4 in)))

(defun print-ip-header-raw (iph)
  (flet ((print-help (name data)
		   (format t "~20@A : ~{~2,'0X~^ ~}~%" name (map 'list #'char-code data))))
	(print-help "version-ihl" (ip-header-version-ihl iph))
	(print-help "type-of-service" (ip-header-type-of-service iph))
	(print-help "total-length " (ip-header-total-length iph))
	(print-help "identification " (ip-header-identification iph))
	(print-help "flags-fragment-offset " (ip-header-flags-fragment-offset iph))
	(print-help "time-to-live " (ip-header-time-to-live iph))
	(print-help "protocol" (ip-header-protoclo iph))
	(print-help "header-checksum" (ip-header-header-checksum iph))
	(print-help "source-ip-address" (ip-header-source-ip-address iph))
	(print-help "source-ip-address" (ip-header-destination-ip-address iph))))

(defparameter pcap-header-info
  '((tcpdump-magic . 4)
	(major-version . 2)
	(minor-version . 2)
	(time-zone . 4)
	(sigfigs . 4)
	(scaplen . 4)
	(link-type . 4)))

(defun printer-help (as)
  `(format t "~20@A : ~{~2,'0X~^ ~}~%" ,(symbol-name (car as)) (map 'list #'char-code (read-n-char ,(cdr as)))))

#|
(defmacro def-printer (name slist)
  `(defun (concat "print-" (symbol-name ',name)) (bin-str)
	 (with-input-from-string (*standard-input* bin-str)
	   (printer-help (car ,slist)))))


(defmacro def-printer (name slist)
  `(defun (concat "print-" ,name)
	 (with-input-from-string (*standard-input* bin-str)
	   ,@(mapcar #'printer-help ',slist)))))


(defstruct pcap-header
  tcpdump-magic major-version minor-version time-zone sigfigs scaplen link-type)
|#
