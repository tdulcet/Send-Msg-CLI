import ctypes
import logging
import sys
from ctypes.util import find_library
from datetime import datetime, timedelta
from email.message import EmailMessage, MIMEPart
from email.policy import SMTP

import configuration
import send

WARNDAYS = 3

libgpgme = find_library("gpgme")
gpgme = None
if libgpgme:
	gpgme = ctypes.CDLL("gpgme" if sys.platform == "win32" else libgpgme)

	class gpgme_subkey_t(ctypes.Structure):
		pass

	gpgme_subkey_t._fields_ = (
		("next", ctypes.POINTER(gpgme_subkey_t)),
		("bitfield", ctypes.c_uint),
		("pubkey_algo", ctypes.c_uint),
		("length", ctypes.c_uint),
		("keyid", ctypes.c_char_p),
		("_keyid", ctypes.c_char * 17),
		("fpr", ctypes.c_char_p),
		("timestamp", ctypes.c_long),
		("expires", ctypes.c_long),
		("card_number", ctypes.c_char_p),
		("curve", ctypes.c_char_p),
		("keygrip", ctypes.c_char_p),
	)

	class gpgme_sig_notation_t(ctypes.Structure):
		pass

	gpgme_sig_notation_t._fields_ = (
		("next", ctypes.POINTER(gpgme_sig_notation_t)),
		("name", ctypes.c_char_p),
		("value", ctypes.c_char_p),
		("name_len", ctypes.c_int),
		("value_len", ctypes.c_int),
		("flags", ctypes.c_uint),
		("bitfield", ctypes.c_uint),
	)

	class gpgme_key_sig_t(ctypes.Structure):
		pass

	gpgme_key_sig_t._fields_ = (
		("next", ctypes.POINTER(gpgme_key_sig_t)),
		("bitfield", ctypes.c_uint),
		("pubkey_algo", ctypes.c_uint),
		("keyid", ctypes.c_char_p),
		("_keyid", ctypes.c_char * 17),
		("timestamp", ctypes.c_long),
		("expires", ctypes.c_long),
		("status", ctypes.c_uint),
		("class", ctypes.c_uint),
		("uid", ctypes.c_char_p),
		("name", ctypes.c_char_p),
		("email", ctypes.c_char_p),
		("comment", ctypes.c_char_p),
		("sig_class", ctypes.c_uint),
		("notations", ctypes.POINTER(gpgme_sig_notation_t)),
		("_last_notation", ctypes.POINTER(gpgme_sig_notation_t)),
	)

	class gpgme_tofu_info_t(ctypes.Structure):
		pass

	gpgme_tofu_info_t._fields_ = (
		("next", ctypes.POINTER(gpgme_tofu_info_t)),
		("bitfield", ctypes.c_uint),
		("signcount", ctypes.c_ushort),
		("encrcount", ctypes.c_ushort),
		("signfirst", ctypes.c_ulong),
		("signlast", ctypes.c_ulong),
		("encrfirst", ctypes.c_ulong),
		("encrlast", ctypes.c_ulong),
		("description", ctypes.c_char_p),
	)

	class gpgme_user_id_t(ctypes.Structure):
		pass

	gpgme_user_id_t._fields_ = (
		("next", ctypes.POINTER(gpgme_user_id_t)),
		("bitfield", ctypes.c_uint),
		("validity", ctypes.c_uint),
		("uid", ctypes.c_char_p),
		("name", ctypes.c_char_p),
		("email", ctypes.c_char_p),
		("comment", ctypes.c_char_p),
		("signatures", ctypes.POINTER(gpgme_key_sig_t)),
		("_last_keysig", ctypes.POINTER(gpgme_key_sig_t)),
		("address", ctypes.c_char_p),
		("tofu", ctypes.POINTER(gpgme_tofu_info_t)),
		("last_update", ctypes.c_ulong),
	)

	class gpgme_key_t(ctypes.Structure):
		_fields_ = (
			("_refs", ctypes.c_uint),
			("bitfield", ctypes.c_uint),
			("protocol", ctypes.c_uint),
			("issuer_serial", ctypes.c_char_p),
			("issuer_name", ctypes.c_char_p),
			("chain_id", ctypes.c_char_p),
			("owner_trust", ctypes.c_uint),
			("subkeys", ctypes.POINTER(gpgme_subkey_t)),
			("uids", ctypes.POINTER(gpgme_user_id_t)),
			("_last_subkey", ctypes.POINTER(gpgme_subkey_t)),
			("_last_uid", ctypes.POINTER(gpgme_user_id_t)),
			("keylist_mode", ctypes.c_uint),
			("fpr", ctypes.c_char_p),
			("last_update", ctypes.c_ulong),
		)

	class gpgme_invalid_key_t(ctypes.Structure):
		pass

	gpgme_invalid_key_t._fields_ = (
		("next", ctypes.POINTER(gpgme_invalid_key_t)),
		("fpr", ctypes.c_char_p),
		("reason", ctypes.c_uint),
	)

	class gpgme_new_signature_t(ctypes.Structure):
		pass

	gpgme_new_signature_t._fields_ = (
		("next", ctypes.POINTER(gpgme_new_signature_t)),
		("type", ctypes.c_uint),
		("pubkey_algo", ctypes.c_uint),
		("hash_algo", ctypes.c_uint),
		("_obsolete_class", ctypes.c_ulong),
		("timestamp", ctypes.c_long),
		("fpr", ctypes.c_char_p),
		("_obsolete_class_2", ctypes.c_uint),
		("sig_class", ctypes.c_uint),
	)

	class gpgme_sign_result_t(ctypes.Structure):
		_fields_ = (("invalid_signers", ctypes.POINTER(gpgme_invalid_key_t)), ("signatures", ctypes.POINTER(gpgme_new_signature_t)))

	gpgme_passphrase_cb_t = ctypes.CFUNCTYPE(
		ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_int
	)

	@gpgme_passphrase_cb_t
	def passphrase_callback(hook, uid_hint, _passphrase_info, prev_was_bad, fd):
		# Work from a config file
		if not prev_was_bad:
			passphrase = hook
			if passphrase.lower() == b"config":
				if uid_hint:
					print("User ID: {}".format(uid_hint.decode()))
				passphrase = configuration.config_pgp().encode()

			buf = passphrase + b"\n"
			gpgme.gpgme_io_write(fd, buf, len(buf))
			return 0
		return 99  # GPG_ERR_CANCELED

	# gpgme.gpgme_strerror.restype = ctypes.c_char_p
	# gpgme.gpgme_strsource.restype = ctypes.c_char_p

	gpgme.gpgme_check_version.argtypes = (ctypes.c_char_p,)
	gpgme.gpgme_check_version.restype = ctypes.c_char_p

	# gpgme.gpgme_set_locale.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p)
	# gpgme.gpgme_set_locale.restype = ctypes.c_uint

	gpgme.gpgme_io_write.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t)
	gpgme.gpgme_io_write.restype = ctypes.c_ssize_t

	gpgme.gpgme_engine_check_version.argtypes = (ctypes.c_int,)
	gpgme.gpgme_engine_check_version.restype = ctypes.c_uint

	gpgme.gpgme_new.argtypes = (ctypes.c_void_p,)
	gpgme.gpgme_new.restype = ctypes.c_uint

	gpgme.gpgme_set_protocol.argtypes = (ctypes.c_void_p, ctypes.c_int)
	gpgme.gpgme_set_protocol.restype = ctypes.c_uint

	gpgme.gpgme_op_keylist_start.argtypes = (ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int)
	gpgme.gpgme_op_keylist_start.restype = ctypes.c_uint

	gpgme.gpgme_op_keylist_next.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(gpgme_key_t)))
	gpgme.gpgme_op_keylist_next.restype = ctypes.c_uint

	gpgme.gpgme_op_keylist_end.argtypes = (ctypes.c_void_p,)
	gpgme.gpgme_op_keylist_end.restype = ctypes.c_uint

	gpgme.gpgme_signers_add.argtypes = (ctypes.c_void_p, ctypes.POINTER(gpgme_key_t))
	gpgme.gpgme_signers_add.restype = ctypes.c_uint

	gpgme.gpgme_set_pinentry_mode.argtypes = (ctypes.c_void_p, ctypes.c_int)
	gpgme.gpgme_set_pinentry_mode.restype = ctypes.c_uint

	gpgme.gpgme_set_passphrase_cb.argtypes = (ctypes.c_void_p, gpgme_passphrase_cb_t, ctypes.c_void_p)
	# gpgme.gpgme_set_passphrase_cb.restype = None

	gpgme.gpgme_set_armor.argtypes = (ctypes.c_void_p, ctypes.c_int)
	# gpgme.gpgme_set_armor.restype = None

	gpgme.gpgme_data_new_from_mem.argtypes = (ctypes.POINTER(ctypes.c_void_p), ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int)
	gpgme.gpgme_data_new_from_mem.restype = ctypes.c_uint

	gpgme.gpgme_data_new.argtypes = (ctypes.POINTER(ctypes.c_void_p),)
	gpgme.gpgme_data_new.restype = ctypes.c_uint

	gpgme.gpgme_op_sign.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int)
	gpgme.gpgme_op_sign.restype = ctypes.c_uint

	gpgme.gpgme_op_sign_result.argtypes = (ctypes.c_void_p,)
	gpgme.gpgme_op_sign_result.restype = ctypes.POINTER(gpgme_sign_result_t)

	gpgme.gpgme_hash_algo_name.argtypes = (ctypes.c_uint,)
	gpgme.gpgme_hash_algo_name.restype = ctypes.c_char_p

	gpgme.gpgme_data_release.argtypes = (ctypes.c_void_p,)
	# gpgme.gpgme_data_release.restype = None

	gpgme.gpgme_key_unref.argtypes = (ctypes.POINTER(gpgme_key_t),)
	# gpgme.gpgme_key_unref.restype = None

	gpgme.gpgme_release.argtypes = (ctypes.c_void_p,)
	# gpgme.gpgme_release.restype = None

	gpgme.gpgme_data_rewind.argtypes = (ctypes.c_void_p,)
	gpgme.gpgme_data_rewind.restype = ctypes.c_uint

	gpgme.gpgme_data_read.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t)
	gpgme.gpgme_data_read.restype = ctypes.c_ssize_t

	gpgme.gpgme_check_version(None)
	# gpgme.gpgme_set_locale(None, locale.LC_ALL, locale.setlocale(locale.LC_ALL, ""))


class PGPError(OSError):
	__slots__ = ()


def gpgme_err_code(error):
	return error & (65536 - 1)  # GPG_ERR_CODE_MASK


def passphrase_checks(args, now, fromaddress):
	"""Does a number of checks if a user indicated they watn to sign with a GPG key to utilize PGP/MIME."""
	if gpgme is None:
		msg = "GNU Privacy Guard is not installed"
		raise RuntimeError(msg)

	if gpgme.gpgme_engine_check_version(0):  # GPGME_PROTOCOL_OpenPGP
		msg = "GPG does not support OpenPGP"
		raise PGPError(msg)

	context = ctypes.c_void_p()
	if gpgme.gpgme_new(ctypes.byref(context)):
		msg = "Failed to create new context"
		raise PGPError(msg)

	try:
		if gpgme.gpgme_set_protocol(context, 0):  # GPGME_PROTOCOL_OpenPGP
			msg = "Failed to set protocol to OpenPGP"
			raise PGPError(msg)

		# check if GPG key exists
		# ("gpg", "--pinentry-mode", "loopback", "--batch", "-o", os.devnull, "-ab", "-u", fromaddress, "--passphrase-fd", "0", f.name)
		if gpgme.gpgme_op_keylist_start(context, fromaddress.encode(), 0):
			msg = "Failed to start getting list of keys"
			raise PGPError(msg)

		key = ctypes.POINTER(gpgme_key_t)()

		error = gpgme.gpgme_op_keylist_next(context, ctypes.byref(key))
		if error:
			if gpgme_err_code(error) == 16383:  # GPG_ERR_EOF
				msg = "A PGP key pair does not yet exist for {!r}.".format(fromaddress)
				raise ValueError(msg)
			msg = "Failed to get next key"
			raise PGPError(msg)

		try:
			if gpgme.gpgme_op_keylist_end(context):
				msg = "Failed to stop getting list of keys"
				raise PGPError(msg)

			if gpgme.gpgme_signers_add(context, key):
				msg = "Failed to add key to list of signers"
				raise PGPError(msg)

			# check if GPG key will expire soon or has expired
			# ("gpg", "-k", "--with-colons", fromaddress)
			date = key.contents.subkeys.contents.expires

			if date:
				date = datetime.fromtimestamp(date)
				# ("gpg", "--fingerprint", "--with-colons", fromaddress)
				# keyid = key.contents.subkeys.contents.keyid.decode()
				fingerprint = key.contents.subkeys.contents.fpr.decode()

				if date > now:
					delta = date - now
					if delta < timedelta(days=WARNDAYS):
						logging.warning(
							"The PGP key pair for %r with fingerprint %s expires in less than %s days %s.",
							fromaddress,
							fingerprint,
							WARNDAYS,
							date.strftime("%c"),
						)
				else:
					msg = "The PGP key pair for {!r} with fingerprint {} expired {:%c}.".format(fromaddress, fingerprint, date)
					raise ValueError(msg)

			if gpgme.gpgme_set_pinentry_mode(context, 4):  # GPGME_PINENTRY_MODE_LOOPBACK
				msg = "Failed to set pinentry mode"
				raise PGPError(msg)

			passphrase = args.passphrase.encode()
			gpgme.gpgme_set_passphrase_cb(context, passphrase_callback, passphrase)

			gpgme.gpgme_set_armor(context, 1)

			data = b"\n"
			ain = ctypes.c_void_p()
			if gpgme.gpgme_data_new_from_mem(ctypes.byref(ain), data, len(data), 0):
				msg = "Failed to create data buffer"
				raise PGPError(msg)

			out = ctypes.c_void_p()
			if gpgme.gpgme_data_new(ctypes.byref(out)):
				msg = "Failed to create data buffer"
				raise PGPError(msg)

			error = gpgme.gpgme_op_sign(context, ain, out, 1)  # GPGME_SIG_MODE_DETACH
			if error:
				if gpgme_err_code(error) == 11:  # GPG_ERR_BAD_PASSPHRASE
					msg = "The passphrase was incorrect."
					raise ValueError(msg)
				msg = "Failed to sign message"
				raise PGPError(msg)

			gpgme.gpgme_data_release(ain)
			gpgme.gpgme_data_release(out)
		finally:
			gpgme.gpgme_key_unref(key)
	finally:
		gpgme.gpgme_release(context)


def pgp(args, fromaddress, lang):
	"""Signs message + attachments with PGP key."""
	msg = MIMEPart()
	if args.message:
		msg.set_content(args.message, cte="quoted-printable")
	if args.language and lang:
		msg["Content-Language"] = lang.replace("_", "-")

	if args.attachments:
		send.attachments(msg, args.attachments)

	context = ctypes.c_void_p()
	if gpgme.gpgme_new(ctypes.byref(context)):
		msg = "Failed to create new context"
		raise PGPError(msg)

	try:
		if gpgme.gpgme_set_protocol(context, 0):  # GPGME_PROTOCOL_OpenPGP
			msg = "Failed to set protocol to OpenPGP"
			raise PGPError(msg)

		# ("gpg", "--pinentry-mode", "loopback", "--batch", "-o", "-", "-ab", "-u", fromaddress, "--passphrase-fd", "0", f.name)
		if gpgme.gpgme_op_keylist_start(context, fromaddress.encode(), 0):
			msg = "Failed to start getting list of keys"
			raise PGPError(msg)

		key = ctypes.POINTER(gpgme_key_t)()

		if gpgme.gpgme_op_keylist_next(context, ctypes.byref(key)):
			msg = "Failed to get next key"
			raise PGPError(msg)

		try:
			if gpgme.gpgme_op_keylist_end(context):
				msg = "Failed to stop getting list of keys"
				raise PGPError(msg)

			if gpgme.gpgme_signers_add(context, key):
				msg = "Failed to add key to list of signers"
				raise PGPError(msg)
		finally:
			gpgme.gpgme_key_unref(key)

		if gpgme.gpgme_set_pinentry_mode(context, 4):  # GPGME_PINENTRY_MODE_LOOPBACK
			msg = "Failed to set pinentry mode"
			raise PGPError(msg)

		passphrase = args.passphrase.encode()
		gpgme.gpgme_set_passphrase_cb(context, passphrase_callback, passphrase)

		gpgme.gpgme_set_armor(context, 1)

		data = msg.as_bytes(policy=SMTP)
		ain = ctypes.c_void_p()
		if gpgme.gpgme_data_new_from_mem(ctypes.byref(ain), data, len(data), 0):
			msg = "Failed to create data buffer"
			raise PGPError(msg)

		try:
			out = ctypes.c_void_p()
			if gpgme.gpgme_data_new(ctypes.byref(out)):
				msg = "Failed to create data buffer"
				raise PGPError(msg)

			try:
				if gpgme.gpgme_op_sign(context, ain, out, 1):  # GPGME_SIG_MODE_DETACH
					msg = "Failed to sign message"
					raise PGPError(msg)

				result = gpgme.gpgme_op_sign_result(context)
				if not result:
					msg = "gpgme_op_sign_result failed"
					raise PGPError(msg)

				hash_name = gpgme.gpgme_hash_algo_name(result.contents.signatures.contents.hash_algo)
				if not hash_name:
					msg = "gpgme_hash_algo_name failed"
					raise PGPError(msg)

				if gpgme.gpgme_data_rewind(out):
					raise PGPError

				buf = ctypes.create_string_buffer(1024)
				pgp_sig = bytearray()
				with memoryview(buf) as view:
					while True:
						readbytes = gpgme.gpgme_data_read(out, buf, len(buf))
						if readbytes <= 0:
							break
						pgp_sig.extend(view[:readbytes])
			finally:
				gpgme.gpgme_data_release(out)
		finally:
			gpgme.gpgme_data_release(ain)
	finally:
		gpgme.gpgme_release(context)

	signmsg = EmailMessage()
	signmsg.make_mixed()
	signmsg.attach(msg)
	signmsg.add_attachment(pgp_sig, maintype="application", subtype="pgp-signature", filename="signature.asc")
	signmsg.replace_header(
		"Content-Type", 'multipart/signed; protocol="application/pgp-signature"; micalg=pgp-' + hash_name.lower().decode()
	)

	send.set_main_headers(args, signmsg)

	return signmsg
