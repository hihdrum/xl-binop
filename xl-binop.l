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

(defun hex-dump (in-str &optional (force-binary nil))
  (let ((str (if force-binary
				 (convert-encoding-to-internal *encoding-binary* in-str)
			   in-str)))
	(format nil "~{~2,'0x~^ ~}" (map 'list #'char-code str))))

(defun display-char (c &optional (sub-c #\.))
  (if (graphic-char-p c)
	  c
	sub-c))

(defun print-hex-dump (str &optional (num 16))
  (let (c (counter 0) (v (make-vector num :element-type 'character :fill-pointer 0))
		  (line-counter 0)
		  (s (make-string-input-stream str)))
	(loop
	  (setq c (read-char s nil :eof))
	  (if (eq c :eof)
		  (progn
			(unless (eq 0 counter)
			  (let* ((address-number (* line-counter num))
					 (addnum (- num counter))
					 (space-str (make-vector (* 3 addnum) :element-type 'character :initial-element #\SPC))
					 (display-str (map 'string #'display-char v)))
				(format t "~8,'0X: ~A~A : ~A~%" address-number (hex-dump v) space-str display-str)))
			(return)))
	  (incf counter)
	  (vector-push c v)
	  (if (= num counter)
		  (progn
			(format t "~8,'0X: ~A : ~A~%"
					(* line-counter num) (hex-dump v) (map 'string #'display-char v))
			(setq counter 0)
			(incf line-counter)
			(setf (fill-pointer v) 0))))))

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

(defun byte-string-to-integer (byte-str)
  (let ((result 0)
		(byte-vector (map 'vector #'char-code byte-str)))
	(dotimes (i (length byte-str) result)
	  (setq result (+ result (ash (svref byte-vector i) (* 8 i)))))))

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
