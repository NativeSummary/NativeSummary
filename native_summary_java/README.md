# native_summary_java

Generate body for native methods in APK. Java part of native_summary project.

build with maven.

Usage: see APKRepacker.main

### develop

install maven https://maven.apache.org/install.html

To debug with source: `mvn dependency:sources` and reload vscode window.

### JNI to Java operations

|       JNI        | Java |
|:----------------:|----|
| Dynamic Register |  -  |
| Call<Ty>Method   |  O  |
| Set/Get<Ty>Field |  O  |
| GetString[UTF]Chars|  O  |
| NewString[UTF]   |  O  |
| NewObject        |  O  |
| Throw[New]       |  O  |
| Get/SetObjectArrayElement  |  O  |
| GetObjectClass       |  O  |

