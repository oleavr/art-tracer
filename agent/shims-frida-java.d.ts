
interface VM {
    perform(function_: any): any;
    getEnv(): NativePointer;
}

declare module "frida-java/lib/vm" {
    interface VMConstructor {
        new(api: JavaApi): VM;
     }
    const VM: VMConstructor;
    export = VM;
}




interface JavaApi {
    artRuntime: NativePointer;  
    vm: NativePointer;  
}

declare module "frida-java" {
    function perform(f: () => void): void;
}


declare module "frida-java/lib/android" {
    function getApi(): JavaApi;   
    function getArtThreadFromEnv(env: NativePointer): NativePointer; 
}


/*declare class VM{
    constructor(api: JavaApi);
    perform(function_: any): any;
}

declare module "frida-java/lib/vm" {
     VM;
}*/

declare const X86Writer: any;