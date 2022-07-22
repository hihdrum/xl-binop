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
