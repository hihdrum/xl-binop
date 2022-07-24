(defmacro with-open-binary-file ((stream filename &rest options) &body body)
  `(with-open-file (,stream ,filename :encoding :binary ,@options)
	 ,@body))

(defmacro with-input-from-binary-file ((stream filename &rest options) &body body)
  `(with-open-binary-file (,stream, filename :direction :input ,@options)
	 ,@body))

(defmacro with-output-to-binary-file ((stream filename &rest options) &body body)
  `(with-open-binary-file (,stream ,filename :direction :output ,@options)
	 ,@body))

(defun make-binary-string-from-string (str)
  (convert-encoding-to-internal *encoding-binary* str))

(defun make-binary-string-input-stream (str)
  (let ((bin-str (make-binary-string-from-string str)))
	(make-string-input-stream bin-str)))

(defun read-n-char (times &optional in eof-error-p eof-value)
  (let ((result (make-vector times :element-type 'character :fill-pointer 0)))
	(dotimes (i times result)
	  (let ((c (read-char in eof-error-p eof-value)))
		(if (eq eof-value c)
			(return result)
		  (vector-push c result))))))

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

(defun make-same-char (n c)
  (with-output-to-string (os)
	(dotimes (i n)
	  (princ c os))))

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
			  (let ((addnum (- 16 counter)))
				(format t "~8,'0X: ~{~2,'0X~^ ~}" (* line-counter 16) (map 'list #'char-code v))
				(format t "~A" (make-same-char (* 3 addnum) #\SPC))
				(format t " : ~A~%" (map 'string #'display-char v)))
			  (return))))
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
  source-ip-address
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
   :source-ip-address (read-n-char 4 in)
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
	(print-help "protocol" (ip-header-protocol iph))
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

(defun proc-one-record (&optional in)
  (let* ((packet-header (read-packet-header-raw in))
		 (len (4-binary-string-to-integer (packet-header-len packet-header)))
		 (raw-packet (read-n-char len in)))
	(print-packet-header-raw packet-header)
	(print-hex-dump raw-packet)))


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
