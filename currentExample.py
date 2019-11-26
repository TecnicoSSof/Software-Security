taint = get()
if taint:
    x = 1
elif not taint:
    mark_safe(escape(taint))
elif True:
    x = 2
else:
    x = 0