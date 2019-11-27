o = get()
x = o
o = escape(o)
send_mail_jinja(o)
send_mail_jinja(request)
RawSQL(x)