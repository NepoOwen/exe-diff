import ida_auto, ida_pro

try:
    ida_auto.auto_wait()
finally:
    ida_pro.qexit(0)
