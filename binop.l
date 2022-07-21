(defun write-byte-list-log (bytes &optional (stream *standard-output*))
  (format-date stream "%Y%m%d%H%M%S000")
  (format stream "~10,'0D" (length bytes))
  (dolist (b bytes)
	(write-char (code-char b) stream)))

(defun write-byte-list-to-file (bytes filepath)
  (with-open-file (s filepath :direction :output :if-doex-not-exist :create :encoding :binary)
	(write-byte-list-log bytes s)))

(defmacro with-open-binary-file ((stream filename &rest options) &body body)
  `(with-open-file (,stream ,filename :encoding :binary ,@options)
	 ,@body))

(defmacro with-output-to-binary-file ((stream filename &rest options) &body body)
  `(with-open-binary-file (,stream ,filename :direction :output ,@options)
	 ,@body))

(defmacro with-input-from-binary-file ((stream filename &rest options) &body body)
  `(with-open-binary-file (,stream, filename :direction :input ,@options)
	 ,@body))

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

(defun %read-n-byte (max-length stream)
  (let ((result (make-vector max-length :element-type 'character :fill-pointer 0))
		(binary-stream (make-string-input-stream
						(convert-encoding-to-internal *encoding-binary* stream))))
	(read-into result binary-stream nil :eof max-length)
	(setq stream binary-stream)
	result))

(defun read-n-byte-from-binary-stream (max-length &optional input-stream eof-error eof-value)
  (let ((result (make-vector max-length :element-type 'character :fill-pointer 0)))
	(read-into result input-stream eof-error eof-value max-length)))

(defun hex-string (str)
  (let ((hstr (format nil "~{~2,'0x ~}"
					  (map 'list #'char-code (convert-encoding-to-internal *encoding-binary* str)))))
	(string-right-trim " " hstr)))

(defun hex-dump (stream)
  (let ((bin-str (convert-encoding-to-internal *encoding-binary* stream)))
	(hex-string bin-str)))

(defun print-hex-dump (n stream)
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

(defun display-char (c &optional (sub-c #\.))
  (if (graphic-char-p c)
	  c
	sub-c))
