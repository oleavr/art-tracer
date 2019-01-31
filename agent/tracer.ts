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

const retainedHandles: any[] = [];  // to keep calbacks alive

let listener: NativePointer;
try {
    listener = makeListener();
} catch (e) {
    log("Shit: " + e.stack);
}

export function trace(callbacks: TraceCallbacks) {
    log("trace() starting up");

    const runtime = api.artRuntime;
    const instrumentation = runtime.add(488);

    const addListener: any = new NativeFunction(
        Module.findExportByName("libart.so","_ZN3art15instrumentation15Instrumentation11AddListenerEPNS0_23InstrumentationListenerEj") as NativePointer,
        "void",
        ["pointer","pointer","uint32"],
        {
            exceptions: ExceptionsBehavior.Propagate
        });
    const enableDeoptimization: any = new NativeFunction(
        Module.findExportByName("libart.so","_ZN3art15instrumentation15Instrumentation20EnableDeoptimizationEv") as NativePointer,
        "void",
        ["pointer"],
        {
            exceptions: ExceptionsBehavior.Propagate
        });
    const deoptimizeEverything: any = new NativeFunction(
        Module.findExportByName("libart.so","_ZN3art15instrumentation15Instrumentation20DeoptimizeEverythingEPKc") as NativePointer,
        "void",
        ["pointer","pointer"],
        {
            exceptions: ExceptionsBehavior.Propagate
        });

    enableDeoptimization(instrumentation);
    deoptimizeEverything(instrumentation, Memory.allocUtf8String("frida"));
    addListener(instrumentation, listener, InstrumentationEvent.MethodEntered /*| InstrumentationEvent.MethodExited | InstrumentationEvent.FieldRead | InstrumentationEvent.FieldWritten*/);
    log("--------> after api: " + JSON.stringify(api));

    


    //488 


    // can call user callbacks
    //console.log("api: " + JSON.stringify(api));
}

function makeListener(): NativePointer {
    const numVirtuals = 11;

    const listener = Memory.alloc(Process.pointerSize);
    retainedHandles.push(listener);

    const vtable = Memory.alloc(numVirtuals * Process.pointerSize);
    retainedHandles.push(vtable);
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
            case 6: { 
                const method = makeFieldRead();
                Memory.writePointer(vtable.add(i * Process.pointerSize), method);
                break; 
            } 
            case 7: { 
                const method = makeFieldWritten();
                Memory.writePointer(vtable.add(i * Process.pointerSize), method);
                break; 
            }
            default: { 
                const method = makeListenerMethod("vmethod" + i);
                Memory.writePointer(vtable.add(i * Process.pointerSize), method);
                break; 
            } 
        } 
        /*
        // Call-back for when we read from a field.
  virtual void FieldRead(Thread* thread, mirror::Object* this_object, ArtMethod* method,
                         uint32_t dex_pc, ArtField* field) = 0;

  // Call-back for when we write into a field.
  virtual void FieldWritten(Thread* thread, mirror::Object* this_object, ArtMethod* method,
                            uint32_t dex_pc, ArtField* field, const JValue& field_value) = 0;

         */
        //const method = (i === 2) ? makeEnterMethod() : makeListenerMethod("vmethod" + i);
        //Memory.writePointer(vtable.add(i * Process.pointerSize), method);
    }

    return listener;
}



function makeFieldRead(): NativePointer {
    const callback = new NativeCallback((self: NativePointer, thread: NativePointer, thisObject: NativePointer, method: NativePointer, dexPc: number, field: NativePointer): void => {
        log("FieldRead() thisObject=" + thisObject + " method=" + method+ " fieldObject="+field);
    }, "void", ["pointer", "pointer", "pointer", "pointer", "uint32","pointer"]);
    retainedHandles.push(callback);

    return callback;
}
function makeFieldWritten(): NativePointer {
    const callback = new NativeCallback((self: NativePointer, thread: NativePointer, thisObject: NativePointer, method: NativePointer, dexPc: number, field: NativePointer, field_value: NativePointer): void => {
        log("FieldWritten() thisObject=" + thisObject + " method=" + method);
    }, "void", ["pointer", "pointer", "pointer", "pointer", "uint32","pointer","pointer"]);
    retainedHandles.push(callback);

    return callback;
}


function makeMethodEntered(): NativePointer {
    const callback = new NativeCallback((self: NativePointer, thread: NativePointer, thisObject: NativePointer, method: NativePointer, dexPc: number): void => {
        log("MethodEntered() thisObject=" + thisObject + " method=" + method);
    }, "void", ["pointer", "pointer", "pointer", "pointer", "uint32"]);
    retainedHandles.push(callback);

    return callback;
}
function makeMethodExited(): NativePointer {
    const callback = new NativeCallback((self: NativePointer, thread: NativePointer, thisObject: NativePointer, method: NativePointer, dexPc: number, returnValue: NativePointer): void => {
        log("MethodExited() thisObject=" + thisObject + " method=" + method + " JValue=" + returnValue);
    }, "void", ["pointer", "pointer", "pointer", "pointer", "uint32","pointer"]);
    retainedHandles.push(callback);
    return callback;
}

function makeListenerMethod(name: string): NativePointer {
    const callback = new NativeCallback((self: NativePointer, thread: NativePointer): void => {
        log(name + " was called!");
    }, "void", ["pointer", "pointer"]);
    retainedHandles.push(callback);

    return callback;
}