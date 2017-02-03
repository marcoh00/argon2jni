# argon2jni

argon2jni is a JNI (Java Native Interface) wrapper using the [official Argon2 C library](https://github.com/P-H-C/phc-winner-argon2).

## What is it?

[Argon2](https://en.wikipedia.org/wiki/Argon2) is a memory and computing intensive hash function. It was built to be used as a _Key Derivation Function_ 
and, as such, it is suitable for _Password Hashing_. It was one of the candidates of the [Password Hashing 
Competition](https://en.wikipedia.org/wiki/Password_Hashing_Competition), in which it was selected as the final winner.

This wrapper library makes it usable from the Java programming language and Android in particular.

## How to build

This repository can be cloned project using

```shell
git clone --recursive "https://github.com/marcoh00/argon2jni.git"
```

When using Android it can be imported as a module from Android Studio by choosing:

File > New > Import Module...

Make sure you compile it as a dependency of your main project. Inside build.gradle:

```gradle
dependencies {
// ...
compile project(':argon2jni')
// ...
}
```

When using plain java, you can use a precompiled JAR file, which will be provided in the future. In the meantime, you have to include the source code in 
some way. The JNI library can be built using [CMake](https://cmake.org). The CMakeLists.txt builds just fine as long as JNI headers are installed. It 
does not have any dependencies on Android.
