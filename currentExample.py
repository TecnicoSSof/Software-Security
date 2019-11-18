taint = get()

if False:
    x = 1
elif True:
    x = 2
elif taint:
    x = 1

else:
    x = 3

mark_safe(escape(x))

