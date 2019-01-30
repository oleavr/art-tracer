import { getApi } from "frida-java/lib/android";
import { log } from "./logger";
const api = getApi();

export interface TraceCallbacks {
    onEnter(methodName: string): void;
    onLeave(methodName: string): void;
}
enum InstrumentationEvent {
    MethodEntered = 0x1,
    MethodExited = 0x2,
    MethodUnwind = 0x4,
    DexPcMoved = 0x8,
    FieldRead = 0x10,
    FieldWritten = 0x20,
    ExceptionCaught = 0x40,
    Branch = 0x80,
    InvokeVirtualOrInterface = 0x100,
}

/*interface JValue {
    z: number,
    b: number;
    c: number;
    s: number;
    i: number;
    j: number;
    f: number;
    d: number;
    l: NativePointer;
}*/

export function trace(callbacks: TraceCallbacks) {
    log("--------> before api___: " + JSON.stringify(api));
    const runtime = api.artRuntime;
    const instrumentation = runtime.add(488);

    const addListener  : any= new NativeFunction(
        Module.findExportByName('libart.so','_ZN3art15instrumentation15Instrumentation11AddListenerEPNS0_23InstrumentationListenerEj') as NativePointerValue,'void',['pointer','pointer','uint32'], {exceptions: ExceptionsBehavior.Propagate});
   

    const numVirtuals = 10;

    const listener = Memory.alloc(Process.pointerSize);

    const vtable = Memory.alloc(numVirtuals * Process.pointerSize);
    Memory.writePointer(listener, vtable);

   
    for (let i = 0; i !== numVirtuals; i++) {
        
        switch(i) { 
            case 2: { 
                const method = makeMethodEntered();
                Memory.writePointer(vtable.add(i * Process.pointerSize), method);
                break; 
            } 
            case 3: { 
                const method = makeMethodExited();
                Memory.writePointer(vtable.add(i * Process.pointerSize), method);
                break; 
            } 
            default: { 
                const method = makeListenerMethod("vmethod" + i);
                Memory.writePointer(vtable.add(i * Process.pointerSize), method);
                break; 
            } 
        } 
        
        //const method = (i === 2) ? makeEnterMethod() : makeListenerMethod("vmethod" + i);
        //Memory.writePointer(vtable.add(i * Process.pointerSize), method);
    }

    addListener(instrumentation, listener, InstrumentationEvent.MethodEntered | InstrumentationEvent.MethodExited);
    log("--------> after api: " + JSON.stringify(api));

    


    //488 


    // can call user callbacks
    //console.log("api: " + JSON.stringify(api));
}

const cbs: NativeCallback[] = [];

function makeMethodEntered(): NativePointer {
    const callback = new NativeCallback((self: NativePointer, thread: NativePointer, thisObject: NativePointer, method: NativePointer, dexPc: number): void => {
        log("MethodEntered() thisObject=" + thisObject + " method=" + method);
    }, 'void', ['pointer', 'pointer', 'pointer', 'pointer', 'uint32']);
    cbs.push(callback);

    return callback;
}
function makeMethodExited(): NativePointer {
    const callback = new NativeCallback((self: NativePointer, thread: NativePointer, thisObject: NativePointer, method: NativePointer, dexPc: number, returnValue: NativePointer): void => {
        log("MethodEntered() thisObject=" + thisObject + " method=" + method + " JValue=" + returnValue);
    }, 'void', ['pointer', 'pointer', 'pointer', 'pointer', 'uint32','pointer']);
    cbs.push(callback);

    return callback;
}

function makeListenerMethod(name: string): NativePointer {
    const callback = new NativeCallback((self: NativePointer, thread: NativePointer): void => {
        log(name + " was called!");
    }, 'void', ['pointer', 'pointer']);
    cbs.push(callback);

    return callback;
}