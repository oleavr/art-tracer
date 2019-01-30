interface JavaApi {
    artRuntime: NativePointer;
}

declare module "frida-java/lib/android" {
    function getApi(): JavaApi;
}