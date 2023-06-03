# native summary IR

1. IR type is mostly unused. backend uses an analysis to find the soot type.
1. When number type is not known, prefer Long.
1. All `CallXXXMethodA/CallXXXMethodV` should be converted to non A/V varient before generate to IR.
1. JNI_OnLoad must be first in module func list.

### Function

It's possible that clazz is null.
1. dynamic registered function(registeredBy != null). because clazz resolution is delayed.
2. JNI_OnLoad. this normally will not be converted to actual java function.
