;--------------------------------------------------------------------------------
; pcap header
;--------------------------------------------------------------------------------
(defun pcap-tcpdump-magic (pcap)
  (substring pcap 0 4))

(defun pcap-major-version (pcap)
  (substring pcap 4 6))

(defun pcap-minor-version (pcap)
  (substring pcap 6 8))

(defun pcap-time-zone (pcap)
  (substring pcap 8 12))

(defun pcap-sigfigs (pcap)
  (substring pcap 12 16))

(defun pcap-scaplen (pcap)
  (substring pcap 16 20))

(defun pcap-link-type (pcap)
  (substring pcap 20 24))

(defun read-pcap-header-raw (&optional in)
  (read-n-char 24 in))

(defstruct pcap-header
  tcpdump-magic major-version minor-version time-zone sigfigs scaplen link-type)

(defun %read-pcap-header-raw (&optional in)
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

;--------------------------------------------------------------------------------
; packet header
;--------------------------------------------------------------------------------
(defun packet-time-stamp (paket-header)
  (substring packet-header 0 8))

(defun packet-caplen (packet-header)
  (substring packet-header 8 12))

(defun packet-len (packet-header)
  (substring packet-header 12 16))

(defun read-packet-header-raw (&optional in)
  (read-n-char 16 in))

(defstruct packet-header
  time-stamp caplen len)

(defun %read-packet-header-raw (&optional in)
  (make-packet-header
   :time-stamp (read-n-char 8 in)
   :caplen (read-n-char 4 in)
   :len (read-n-char 4 in)))

(defun %print-packet-header-raw (ph)
  (flet ((print-help (name data)
		   (format t "~20@A : ~{~2,'0X~^ ~}~%" name (map 'list #'char-code data))))
	(print-help "time-stamp" (packet-header-time-stamp ph))
	(print-help "caplen" (packet-header-caplen ph))
	(print-help "len" (packet-header-len ph))))

;--------------------------------------------------------------------------------
; ethernet2
;--------------------------------------------------------------------------------
(defun ethernet2-destination (eth)
  (substring eth 0 6))

(defun ethernet2-source (eth)
  (substring eth 6 12))

(defun ethernet2-type (eth)
  (substring eth 12 16))

(defun read-ethernet2-raw (&optional in)
  (read-n-char 16 in))

(defun mac-address-string (mac-str)
  (format nil "~{~2,'0X~^:~}" (map 'list #'char-code mac-str)))

(defstruct ethernet2
  destination
  source
  type)

(defun %read-ethernet2-raw (&optional in)
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

;--------------------------------------------------------------------------------
; IP
;--------------------------------------------------------------------------------
(defun ip-version (ip)
  (ash (char-code (svref ip 0)) -4))

(defun ip-header-length (ip)
  (logand #x0f (char-code (svref ip 0))))

(defun read-ip-header-raw (&optional in)
  (read-n-char 24 in))

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

(defun %read-ip-header-raw (&optional in)
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
		 (len (byte-string-to-integer (packet-header-len packet-header)))
		 (raw-packet (read-n-char len in)))
	(print-packet-header-raw packet-header)
	(print-hex-dump raw-packet)))
